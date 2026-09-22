// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

// Copyright Authors of Cilium

package parser

import (
	"log/slog"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	pb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	observerTypes "github.com/cilium/cilium/pkg/hubble/observer/types"
	"github.com/cilium/cilium/pkg/hubble/parser/agent"
	"github.com/cilium/cilium/pkg/hubble/parser/debug"
	"github.com/cilium/cilium/pkg/hubble/parser/errors"
	"github.com/cilium/cilium/pkg/hubble/parser/getters"
	"github.com/cilium/cilium/pkg/hubble/parser/options"
	"github.com/cilium/cilium/pkg/hubble/parser/seven"
	"github.com/cilium/cilium/pkg/hubble/parser/sock"
	"github.com/cilium/cilium/pkg/hubble/parser/threefour"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
	"github.com/cilium/cilium/pkg/proxy/accesslog"
)

// Decoder is an interface for the parser.
// It decodes a monitor event into a hubble event.
type Decoder interface {
	// Decode transforms a monitor event into a hubble event.
	Decode(monitorEvent *observerTypes.MonitorEvent) (*v1.Event, error)
}

// Parser for all flows
type Parser struct {
	l34  *threefour.Parser
	l7   *seven.Parser
	dbg  *debug.Parser
	sock *sock.Parser
}

// New creates a new parser
func New(
	log *slog.Logger,
	endpointGetter getters.EndpointGetter,
	identityGetter getters.IdentityGetter,
	dnsGetter getters.DNSGetter,
	ipGetter getters.IPGetter,
	serviceGetter getters.ServiceGetter,
	linkGetter getters.LinkGetter,
	cgroupGetter getters.PodMetadataGetter,
	opts ...options.Option,
) (*Parser, error) {

	l34, err := threefour.New(log, endpointGetter, identityGetter, dnsGetter, ipGetter, serviceGetter, linkGetter, opts...)
	if err != nil {
		return nil, err
	}

	l7, err := seven.New(log, dnsGetter, ipGetter, serviceGetter, endpointGetter, opts...)
	if err != nil {
		return nil, err
	}

	dbg, err := debug.New(log, endpointGetter, opts...)
	if err != nil {
		return nil, err
	}

	sock, err := sock.New(log, endpointGetter, identityGetter, dnsGetter, ipGetter, serviceGetter, cgroupGetter, opts...)
	if err != nil {
		return nil, err
	}

	return &Parser{
		l34:  l34,
		l7:   l7,
		dbg:  dbg,
		sock: sock,
	}, nil
}

func lostEventSourceToProto(source int) pb.LostEventSource {
	switch source {
	case observerTypes.LostEventSourcePerfRingBuffer:
		return pb.LostEventSource_PERF_EVENT_RING_BUFFER
	case observerTypes.LostEventSourceEventsQueue:
		return pb.LostEventSource_OBSERVER_EVENTS_QUEUE
	case observerTypes.LostEventSourceHubbleRingBuffer:
		return pb.LostEventSource_HUBBLE_RING_BUFFER
	default:
		return pb.LostEventSource_UNKNOWN_LOST_EVENT_SOURCE
	}
}

// decodedEvent groups the messages that every decoded event needs into one
// allocation. They are created together, have identical lifetime, and are
// reachable only through the Event at the root.
type decodedEvent struct {
	ev v1.Event
	ts timestamppb.Timestamp
}

func newDecodedEvent(t time.Time) *decodedEvent {
	d := new(decodedEvent)
	d.ts = timestamppb.Timestamp{
		Seconds: t.Unix(),
		Nanos:   int32(t.Nanosecond()),
	}
	d.ev.Timestamp = &d.ts
	return d
}

// decodedFlowEvent is decodedEvent plus the Flow and its Emitter, for the
// payloads that produce a flow.
//
// The Emitter is co-allocated rather than shared from a package-level
// singleton. It is the same number of allocations either way, since it sits
// inside this struct, and it keeps every flow owning its own messages.
type decodedFlowEvent struct {
	ev      v1.Event
	ts      timestamppb.Timestamp
	flow    pb.Flow
	emitter pb.Emitter
}

func newDecodedFlowEvent(t time.Time, uuid, nodeName string) *decodedFlowEvent {
	d := new(decodedFlowEvent)
	d.ts = timestamppb.Timestamp{
		Seconds: t.Unix(),
		Nanos:   int32(t.Nanosecond()),
	}
	d.ev.Timestamp = &d.ts
	d.emitter = pb.Emitter{
		Name:    v1.FlowEmitter,
		Version: v1.FlowEmitterVersion,
	}
	d.flow.Emitter = &d.emitter
	d.flow.Uuid = uuid
	// FIXME: Time and NodeName are now part of GetFlowsResponse. We populate
	// these fields for compatibility with old clients.
	d.flow.Time = &d.ts
	d.flow.NodeName = nodeName
	return d
}

// Decode decodes a cilium monitor 'payload' and returns a v1.Event with
// the Event field populated.
func (p *Parser) Decode(monitorEvent *observerTypes.MonitorEvent) (*v1.Event, error) {
	if monitorEvent == nil {
		return nil, errors.ErrEmptyData
	}

	switch payload := monitorEvent.Payload.(type) {
	case *observerTypes.PerfEvent:
		if len(payload.Data) == 0 {
			return nil, errors.ErrEmptyData
		}

		if payload.Data[0] == monitorAPI.MessageTypeDebug {
			// Debug and TraceSock are both perf ring buffer events without any
			// associated captured network packet header, so we treat them
			// separately.
			//
			// Debug events carry no flow, so they use the smaller struct; the
			// flow-carrying one would keep a whole unused pb.Flow alive for as
			// long as the event is retained.
			dbg, err := p.dbg.Decode(payload.Data, payload.CPU)
			if err != nil {
				return nil, err
			}
			d := newDecodedEvent(monitorEvent.Timestamp)
			d.ev.Event = dbg
			return &d.ev, nil
		}

		d := newDecodedFlowEvent(monitorEvent.Timestamp, monitorEvent.UUID.String(), monitorEvent.NodeName)
		switch payload.Data[0] {
		case monitorAPI.MessageTypeTraceSock:
			if err := p.sock.Decode(payload.Data, &d.flow); err != nil {
				return nil, err
			}
		default:
			if err := p.l34.Decode(payload.Data, &d.flow); err != nil {
				return nil, err
			}
		}
		d.ev.Event = &d.flow
		return &d.ev, nil
	case *observerTypes.AgentEvent:
		switch payload.Type {
		case monitorAPI.MessageTypeAccessLog:
			logrecord, ok := payload.Message.(accesslog.LogRecord)
			if !ok {
				return nil, errors.ErrInvalidAgentMessageType
			}
			d := newDecodedFlowEvent(monitorEvent.Timestamp, monitorEvent.UUID.String(), monitorEvent.NodeName)
			if err := p.l7.Decode(&logrecord, &d.flow); err != nil {
				return nil, err
			}
			d.ev.Event = &d.flow
			return &d.ev, nil
		case monitorAPI.MessageTypeAgent:
			agentNotifyMessage, ok := payload.Message.(monitorAPI.AgentNotifyMessage)
			if !ok {
				return nil, errors.ErrInvalidAgentMessageType
			}
			d := newDecodedEvent(monitorEvent.Timestamp)
			d.ev.Event = agent.NotifyMessageToProto(agentNotifyMessage)
			return &d.ev, nil
		default:
			return nil, errors.ErrUnknownEventType
		}
	case *observerTypes.LostEvent:
		lostEvent := &pb.LostEvent{
			Source:        lostEventSourceToProto(payload.Source),
			NumEventsLost: payload.NumLostEvents,
			Cpu: &wrapperspb.Int32Value{
				Value: int32(payload.CPU),
			},
		}
		if !payload.First.IsZero() {
			lostEvent.First = timestamppb.New(payload.First)
		}
		if !payload.Last.IsZero() {
			lostEvent.Last = timestamppb.New(payload.Last)
		}
		d := newDecodedEvent(monitorEvent.Timestamp)
		d.ev.Event = lostEvent
		return &d.ev, nil
	case nil:
		d := newDecodedEvent(monitorEvent.Timestamp)
		return &d.ev, errors.ErrEmptyData
	default:
		return nil, errors.ErrUnknownEventType
	}
}
