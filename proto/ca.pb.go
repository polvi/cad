// Code generated by protoc-gen-go.
// source: ca.proto
// DO NOT EDIT!

/*
Package proto is a generated protocol buffer package.

It is generated from these files:
	ca.proto

It has these top-level messages:
	GetCaCertParams
	SignParams
	SignedCert
	CaCert
*/
package proto

import proto1 "github.com/golang/protobuf/proto"

import (
	context "golang.org/x/net/context"
	grpc "google.golang.org/grpc"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto1.Marshal

type GetCaCertParams struct {
}

func (m *GetCaCertParams) Reset()         { *m = GetCaCertParams{} }
func (m *GetCaCertParams) String() string { return proto1.CompactTextString(m) }
func (*GetCaCertParams) ProtoMessage()    {}

type SignParams struct {
	CSR             []byte `protobuf:"bytes,1,opt,proto3" json:"CSR,omitempty"`
	DurationSeconds int64  `protobuf:"varint,2,opt" json:"DurationSeconds,omitempty"`
}

func (m *SignParams) Reset()         { *m = SignParams{} }
func (m *SignParams) String() string { return proto1.CompactTextString(m) }
func (*SignParams) ProtoMessage()    {}

type SignedCert struct {
	Cert []byte `protobuf:"bytes,1,opt,proto3" json:"Cert,omitempty"`
}

func (m *SignedCert) Reset()         { *m = SignedCert{} }
func (m *SignedCert) String() string { return proto1.CompactTextString(m) }
func (*SignedCert) ProtoMessage()    {}

type CaCert struct {
	Cert []byte `protobuf:"bytes,1,opt,proto3" json:"Cert,omitempty"`
}

func (m *CaCert) Reset()         { *m = CaCert{} }
func (m *CaCert) String() string { return proto1.CompactTextString(m) }
func (*CaCert) ProtoMessage()    {}

func init() {
}

// Client API for Ca service

type CaClient interface {
	GetCaCert(ctx context.Context, in *GetCaCertParams, opts ...grpc.CallOption) (*CaCert, error)
	SignCaCert(ctx context.Context, in *SignParams, opts ...grpc.CallOption) (*SignedCert, error)
	SignCert(ctx context.Context, in *SignParams, opts ...grpc.CallOption) (*SignedCert, error)
}

type caClient struct {
	cc *grpc.ClientConn
}

func NewCaClient(cc *grpc.ClientConn) CaClient {
	return &caClient{cc}
}

func (c *caClient) GetCaCert(ctx context.Context, in *GetCaCertParams, opts ...grpc.CallOption) (*CaCert, error) {
	out := new(CaCert)
	err := grpc.Invoke(ctx, "/proto.Ca/GetCaCert", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *caClient) SignCaCert(ctx context.Context, in *SignParams, opts ...grpc.CallOption) (*SignedCert, error) {
	out := new(SignedCert)
	err := grpc.Invoke(ctx, "/proto.Ca/SignCaCert", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *caClient) SignCert(ctx context.Context, in *SignParams, opts ...grpc.CallOption) (*SignedCert, error) {
	out := new(SignedCert)
	err := grpc.Invoke(ctx, "/proto.Ca/SignCert", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Server API for Ca service

type CaServer interface {
	GetCaCert(context.Context, *GetCaCertParams) (*CaCert, error)
	SignCaCert(context.Context, *SignParams) (*SignedCert, error)
	SignCert(context.Context, *SignParams) (*SignedCert, error)
}

func RegisterCaServer(s *grpc.Server, srv CaServer) {
	s.RegisterService(&_Ca_serviceDesc, srv)
}

func _Ca_GetCaCert_Handler(srv interface{}, ctx context.Context, codec grpc.Codec, buf []byte) (interface{}, error) {
	in := new(GetCaCertParams)
	if err := codec.Unmarshal(buf, in); err != nil {
		return nil, err
	}
	out, err := srv.(CaServer).GetCaCert(ctx, in)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func _Ca_SignCaCert_Handler(srv interface{}, ctx context.Context, codec grpc.Codec, buf []byte) (interface{}, error) {
	in := new(SignParams)
	if err := codec.Unmarshal(buf, in); err != nil {
		return nil, err
	}
	out, err := srv.(CaServer).SignCaCert(ctx, in)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func _Ca_SignCert_Handler(srv interface{}, ctx context.Context, codec grpc.Codec, buf []byte) (interface{}, error) {
	in := new(SignParams)
	if err := codec.Unmarshal(buf, in); err != nil {
		return nil, err
	}
	out, err := srv.(CaServer).SignCert(ctx, in)
	if err != nil {
		return nil, err
	}
	return out, nil
}

var _Ca_serviceDesc = grpc.ServiceDesc{
	ServiceName: "proto.Ca",
	HandlerType: (*CaServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "GetCaCert",
			Handler:    _Ca_GetCaCert_Handler,
		},
		{
			MethodName: "SignCaCert",
			Handler:    _Ca_SignCaCert_Handler,
		},
		{
			MethodName: "SignCert",
			Handler:    _Ca_SignCert_Handler,
		},
	},
	Streams: []grpc.StreamDesc{},
}
