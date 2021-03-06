// Code generated by protoc-gen-go. DO NOT EDIT.
// source: types.proto

/*
Package storagepacker is a generated protocol buffer package.

It is generated from these files:
	types.proto

It has these top-level messages:
	Item
	Bucket
*/
package storagepacker

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"
import google_protobuf "github.com/golang/protobuf/ptypes/any"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

type Item struct {
	ID      string               `protobuf:"bytes,1,opt,name=id" json:"id,omitempty"`
	Message *google_protobuf.Any `protobuf:"bytes,2,opt,name=message" json:"message,omitempty"`
}

func (m *Item) Reset()                    { *m = Item{} }
func (m *Item) String() string            { return proto.CompactTextString(m) }
func (*Item) ProtoMessage()               {}
func (*Item) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{0} }

func (m *Item) GetID() string {
	if m != nil {
		return m.ID
	}
	return ""
}

func (m *Item) GetMessage() *google_protobuf.Any {
	if m != nil {
		return m.Message
	}
	return nil
}

type Bucket struct {
	Key   string  `protobuf:"bytes,1,opt,name=key" json:"key,omitempty"`
	Items []*Item `protobuf:"bytes,2,rep,name=items" json:"items,omitempty"`
}

func (m *Bucket) Reset()                    { *m = Bucket{} }
func (m *Bucket) String() string            { return proto.CompactTextString(m) }
func (*Bucket) ProtoMessage()               {}
func (*Bucket) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{1} }

func (m *Bucket) GetKey() string {
	if m != nil {
		return m.Key
	}
	return ""
}

func (m *Bucket) GetItems() []*Item {
	if m != nil {
		return m.Items
	}
	return nil
}

func init() {
	proto.RegisterType((*Item)(nil), "storagepacker.Item")
	proto.RegisterType((*Bucket)(nil), "storagepacker.Bucket")
}

func init() { proto.RegisterFile("types.proto", fileDescriptor0) }

var fileDescriptor0 = []byte{
	// 181 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xe2, 0xe2, 0x2e, 0xa9, 0x2c, 0x48,
	0x2d, 0xd6, 0x2b, 0x28, 0xca, 0x2f, 0xc9, 0x17, 0xe2, 0x2d, 0x2e, 0xc9, 0x2f, 0x4a, 0x4c, 0x4f,
	0x2d, 0x48, 0x4c, 0xce, 0x4e, 0x2d, 0x92, 0x92, 0x4c, 0xcf, 0xcf, 0x4f, 0xcf, 0x49, 0xd5, 0x07,
	0x4b, 0x26, 0x95, 0xa6, 0xe9, 0x27, 0xe6, 0x55, 0x42, 0x54, 0x2a, 0xb9, 0x71, 0xb1, 0x78, 0x96,
	0xa4, 0xe6, 0x0a, 0xf1, 0x71, 0x31, 0x65, 0xa6, 0x48, 0x30, 0x2a, 0x30, 0x6a, 0x70, 0x06, 0x31,
	0x65, 0xa6, 0x08, 0xe9, 0x71, 0xb1, 0xe7, 0xa6, 0x16, 0x17, 0x27, 0xa6, 0xa7, 0x4a, 0x30, 0x29,
	0x30, 0x6a, 0x70, 0x1b, 0x89, 0xe8, 0x41, 0x0c, 0xd1, 0x83, 0x19, 0xa2, 0xe7, 0x98, 0x57, 0x19,
	0x04, 0x53, 0xa4, 0xe4, 0xca, 0xc5, 0xe6, 0x54, 0x9a, 0x9c, 0x9d, 0x5a, 0x22, 0x24, 0xc0, 0xc5,
	0x9c, 0x9d, 0x5a, 0x09, 0x35, 0x0a, 0xc4, 0x14, 0xd2, 0xe4, 0x62, 0xcd, 0x2c, 0x49, 0xcd, 0x2d,
	0x96, 0x60, 0x52, 0x60, 0xd6, 0xe0, 0x36, 0x12, 0xd6, 0x43, 0x71, 0x9d, 0x1e, 0xc8, 0xfe, 0x20,
	0x88, 0x8a, 0x24, 0x36, 0xb0, 0xe9, 0xc6, 0x80, 0x00, 0x00, 0x00, 0xff, 0xff, 0x01, 0x30, 0x77,
	0x9a, 0xce, 0x00, 0x00, 0x00,
}
