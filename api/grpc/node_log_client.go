package grpc

import (
	"context"
	"fmt"
	"time"

	pb "github.com/AnixOps/anix-agent/v5/api/grpc/v2boardpb"
	"github.com/AnixOps/anix-agent/v5/api/panel"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"
)

const NodeLogService_ReportLogs_FullMethodName = "/v2board.NodeLogService/ReportLogs"

var (
	nodeLogEntryDesc protoreflect.MessageDescriptor
	nodeLogBatchDesc protoreflect.MessageDescriptor

	nodeLogBatchNodeIDField protoreflect.FieldDescriptor
	nodeLogBatchLogsField   protoreflect.FieldDescriptor

	nodeLogEntryLevelField      protoreflect.FieldDescriptor
	nodeLogEntrySourceField     protoreflect.FieldDescriptor
	nodeLogEntryMessageField    protoreflect.FieldDescriptor
	nodeLogEntryTimestampField  protoreflect.FieldDescriptor
	nodeLogEntryFieldsJSONField protoreflect.FieldDescriptor
	nodeLogEntryTraceIDField    protoreflect.FieldDescriptor
)

func init() {
	fileProto := &descriptorpb.FileDescriptorProto{
		Name:    stringPtr("api/grpc/node_log_runtime.proto"),
		Package: stringPtr("v2board"),
		Syntax:  stringPtr("proto3"),
		MessageType: []*descriptorpb.DescriptorProto{
			{
				Name: stringPtr("NodeLogEntry"),
				Field: []*descriptorpb.FieldDescriptorProto{
					newStringField("level", 1),
					newStringField("source", 2),
					newStringField("message", 3),
					newInt64Field("timestamp", 4),
					newStringField("fields_json", 5),
					newStringField("trace_id", 6),
				},
			},
			{
				Name: stringPtr("NodeLogBatchRequest"),
				Field: []*descriptorpb.FieldDescriptorProto{
					newUint32Field("node_id", 1),
					newRepeatedMessageField("logs", 2, ".v2board.NodeLogEntry"),
				},
			},
		},
	}

	fileDesc, err := protodesc.NewFile(fileProto, nil)
	if err != nil {
		panic(err)
	}

	nodeLogEntryDesc = fileDesc.Messages().ByName("NodeLogEntry")
	nodeLogBatchDesc = fileDesc.Messages().ByName("NodeLogBatchRequest")

	nodeLogBatchNodeIDField = nodeLogBatchDesc.Fields().ByName("node_id")
	nodeLogBatchLogsField = nodeLogBatchDesc.Fields().ByName("logs")

	nodeLogEntryLevelField = nodeLogEntryDesc.Fields().ByName("level")
	nodeLogEntrySourceField = nodeLogEntryDesc.Fields().ByName("source")
	nodeLogEntryMessageField = nodeLogEntryDesc.Fields().ByName("message")
	nodeLogEntryTimestampField = nodeLogEntryDesc.Fields().ByName("timestamp")
	nodeLogEntryFieldsJSONField = nodeLogEntryDesc.Fields().ByName("fields_json")
	nodeLogEntryTraceIDField = nodeLogEntryDesc.Fields().ByName("trace_id")
}

func stringPtr(v string) *string {
	return &v
}

func int32Ptr(v int32) *int32 {
	return &v
}

func labelPtr(v descriptorpb.FieldDescriptorProto_Label) *descriptorpb.FieldDescriptorProto_Label {
	return &v
}

func typePtr(v descriptorpb.FieldDescriptorProto_Type) *descriptorpb.FieldDescriptorProto_Type {
	return &v
}

func newStringField(name string, number int32) *descriptorpb.FieldDescriptorProto {
	return &descriptorpb.FieldDescriptorProto{
		Name:   stringPtr(name),
		Number: int32Ptr(number),
		Label:  labelPtr(descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL),
		Type:   typePtr(descriptorpb.FieldDescriptorProto_TYPE_STRING),
	}
}

func newInt64Field(name string, number int32) *descriptorpb.FieldDescriptorProto {
	return &descriptorpb.FieldDescriptorProto{
		Name:   stringPtr(name),
		Number: int32Ptr(number),
		Label:  labelPtr(descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL),
		Type:   typePtr(descriptorpb.FieldDescriptorProto_TYPE_INT64),
	}
}

func newUint32Field(name string, number int32) *descriptorpb.FieldDescriptorProto {
	return &descriptorpb.FieldDescriptorProto{
		Name:   stringPtr(name),
		Number: int32Ptr(number),
		Label:  labelPtr(descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL),
		Type:   typePtr(descriptorpb.FieldDescriptorProto_TYPE_UINT32),
	}
}

func newRepeatedMessageField(name string, number int32, typeName string) *descriptorpb.FieldDescriptorProto {
	return &descriptorpb.FieldDescriptorProto{
		Name:     stringPtr(name),
		Number:   int32Ptr(number),
		Label:    labelPtr(descriptorpb.FieldDescriptorProto_LABEL_REPEATED),
		Type:     typePtr(descriptorpb.FieldDescriptorProto_TYPE_MESSAGE),
		TypeName: stringPtr(typeName),
	}
}

type NodeLogServiceClient interface {
	ReportLogs(ctx context.Context, in *dynamicpb.Message, opts ...grpc.CallOption) (*pb.StatusResponse, error)
}

type nodeLogServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewNodeLogServiceClient(cc grpc.ClientConnInterface) NodeLogServiceClient {
	return &nodeLogServiceClient{cc: cc}
}

func (c *nodeLogServiceClient) ReportLogs(ctx context.Context, in *dynamicpb.Message, opts ...grpc.CallOption) (*pb.StatusResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(pb.StatusResponse)
	if err := c.cc.Invoke(ctx, NodeLogService_ReportLogs_FullMethodName, in, out, cOpts...); err != nil {
		return nil, err
	}
	return out, nil
}

func newNodeLogBatchMessage(nodeID int, entries []panel.NodeLogEntry) (*dynamicpb.Message, error) {
	msg := dynamicpb.NewMessage(nodeLogBatchDesc)
	msg.Set(nodeLogBatchNodeIDField, protoreflect.ValueOfUint32(uint32(nodeID)))

	list := msg.Mutable(nodeLogBatchLogsField).List()
	for _, entry := range entries {
		if entry.Message == "" {
			continue
		}
		item := dynamicpb.NewMessage(nodeLogEntryDesc)
		item.Set(nodeLogEntryLevelField, protoreflect.ValueOfString(entry.Level))
		item.Set(nodeLogEntrySourceField, protoreflect.ValueOfString(entry.Source))
		item.Set(nodeLogEntryMessageField, protoreflect.ValueOfString(entry.Message))
		item.Set(nodeLogEntryFieldsJSONField, protoreflect.ValueOfString(entry.FieldsJSON))
		item.Set(nodeLogEntryTraceIDField, protoreflect.ValueOfString(entry.TraceID))

		ts := entry.Timestamp
		if ts.IsZero() {
			ts = time.Now()
		}
		item.Set(nodeLogEntryTimestampField, protoreflect.ValueOfInt64(ts.Unix()))
		list.Append(protoreflect.ValueOfMessage(item))
	}

	if list.Len() == 0 {
		return nil, fmt.Errorf("no log entries to report")
	}

	return msg, nil
}
