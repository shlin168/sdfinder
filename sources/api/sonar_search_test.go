package api

import (
	"context"
	"log"
	"net"
	"sort"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/test/bufconn"

	pb "github.com/cgboal/sonarsearch/proto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const bufSize = 1024 * 1024

var lis *bufconn.Listener

func StartGrpcServer() *grpc.Server {
	lis = bufconn.Listen(bufSize)
	s := grpc.NewServer()
	pb.RegisterCrobatServer(s, &CrobatServer{})
	go func() {
		if err := s.Serve(lis); err != nil {
			log.Fatalf("Server exited with error: %v", err)
		}
	}()
	return s
}

func bufDialer(context.Context, string) (net.Conn, error) {
	return lis.Dial()
}

type CrobatServer struct {
	pb.CrobatServer
}

func (cs *CrobatServer) GetSubdomains(q *pb.QueryRequest, stream pb.Crobat_GetSubdomainsServer) error {
	domain := q.Query
	for _, fstLvl := range []string{"abc", "test", "abc"} {
		subdomain := fstLvl + "." + domain
		reply := &pb.Domain{
			Domain: subdomain,
		}
		if err := stream.Send(reply); err != nil {
			return err
		}
	}
	if err := stream.Send(&pb.Domain{Domain: "aaa.test.com"}); err != nil {
		return err
	}
	return nil
}

func (cs *CrobatServer) ReverseDNS(q *pb.QueryRequest, stream pb.Crobat_ReverseDNSServer) error {
	for _, subdomain := range []string{"abc.trendmicro.com", "test.trendmicro.com", "abc.trendmicro.com"} {
		reply := &pb.Domain{
			Domain: subdomain,
		}
		if err := stream.Send(reply); err != nil {
			return err
		}
	}
	return nil
}

func TestSonarSearch(t *testing.T) {
	srv := StartGrpcServer()
	defer srv.Stop()

	ctx := context.Background()
	conn, err := grpc.DialContext(ctx, "bufnet", grpc.WithContextDialer(bufDialer), grpc.WithInsecure())
	if err != nil {
		t.Fatalf("Failed to dial bufnet: %v", err)
	}
	defer conn.Close()
	client := pb.NewCrobatClient(conn)
	ss := NewSonarSearch()
	ss.conn = conn
	ss.cli = client
	sds, err := ss.Get(ctx, "TEST.COM")
	require.NoError(t, err)
	sort.Strings(sds)
	assert.Equal(t, []string{"aaa.test.com", "abc.test.com", "test.test.com"}, sds)
	assert.NoError(t, ss.Close())
}

func TestSonarSearchSd(t *testing.T) {
	srv := StartGrpcServer()
	defer srv.Stop()

	ctx := context.Background()
	conn, err := grpc.DialContext(ctx, "bufnet", grpc.WithContextDialer(bufDialer), grpc.WithInsecure())
	if err != nil {
		t.Fatalf("Failed to dial bufnet: %v", err)
	}
	defer conn.Close()
	client := pb.NewCrobatClient(conn)
	ssSbs := NewSonarSearchSbs()
	ssSbs.conn = conn
	ssSbs.cli = client
	sds, err := ssSbs.Get(ctx, "user.github.io")
	require.NoError(t, err)
	sort.Strings(sds)
	assert.Equal(t, []string{"abc.user.github.io", "test.user.github.io"}, sds)
	assert.NoError(t, ssSbs.Close())
}

func TestSonarSearchRvs(t *testing.T) {
	srv := StartGrpcServer()

	ctx := context.Background()
	conn, err := grpc.DialContext(ctx, "bufnet", grpc.WithContextDialer(bufDialer), grpc.WithInsecure())
	if err != nil {
		t.Fatalf("Failed to dial bufnet: %v", err)
	}
	defer conn.Close()
	client := pb.NewCrobatClient(conn)
	ssRvs := NewSonarSearchRvs()
	ssRvs.conn = conn
	ssRvs.cli = client
	sds, err := ssRvs.Get(ctx, "1.2.1.2")
	require.NoError(t, err)
	sort.Strings(sds)
	assert.Equal(t, []string{"abc.trendmicro.com", "test.trendmicro.com"}, sds)
	assert.NoError(t, ssRvs.Close())

	srv.Stop()
}
