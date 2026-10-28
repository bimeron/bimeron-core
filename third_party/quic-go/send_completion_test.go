package quic

import (
	"context"
	"testing"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestSendCompletionWaitsForAllDataAndFINAcknowledgements(t *testing.T) {
	const id protocol.StreamID = 4
	sender := NewMockStreamSender(gomock.NewController(t))
	str := newSendStream(context.Background(), id, sender, newTestStreamFlowControllerWithSendWindow(id, protocol.MaxByteCount), false)
	done := str.SendCompletionContext()
	sender.EXPECT().onHasStreamData(id, str).AnyTimes()
	sender.EXPECT().onHasStreamRetransmission(id, str)
	sender.EXPECT().onStreamCompleted(id)
	_, err := str.Write([]byte("foobar"))
	require.NoError(t, err)
	first, _, _ := str.popStreamFrame(3+expectedFrameHeaderLen(id, 0), protocol.Version1)
	require.NotNil(t, first.Frame)
	require.False(t, first.Frame.Fin)
	require.NoError(t, str.Close())
	require.Error(t, str.Context().Err())
	require.NoError(t, done.Err())
	last, _, _ := str.popStreamFrame(protocol.MaxByteCount, protocol.Version1)
	require.NotNil(t, last.Frame)
	require.True(t, last.Frame.Fin)
	last.Handler.OnAcked(last.Frame)
	require.NoError(t, done.Err(), "FIN ACK alone must not complete an earlier lost frame")
	first.Handler.OnLost(first.Frame)
	retransmit, _ := str.popRetransmissionFrame(protocol.MaxByteCount, protocol.Version1)
	require.NotNil(t, retransmit.Frame)
	require.NoError(t, done.Err())
	retransmit.Handler.OnAcked(retransmit.Frame)
	require.Error(t, done.Err())
	require.Error(t, str.SendCompletionContext().Err())
}

func TestSendCompletionResetAndConnectionShutdown(t *testing.T) {
	for _, mode := range []string{"reset", "shutdown", "late_shutdown"} {
		t.Run(mode, func(t *testing.T) {
			const id protocol.StreamID = 4
			sender := NewMockStreamSender(gomock.NewController(t))
			str := newSendStream(context.Background(), id, sender, newTestStreamFlowControllerWithSendWindow(id, protocol.MaxByteCount), false)
			if mode == "late_shutdown" {
				str.closeForShutdown(context.Canceled)
				require.Error(t, str.SendCompletionContext().Err())
				return
			}
			done := str.SendCompletionContext()
			if mode == "reset" {
				sender.EXPECT().onHasStreamControlFrame(id, str)
				sender.EXPECT().onStreamCompleted(id)
				str.CancelWrite(0)
				require.NoError(t, done.Err())
				frame, ok, _ := str.getControlFrame(monotime.Now())
				require.True(t, ok)
				frame.Handler.OnAcked(frame.Frame)
			} else {
				str.closeForShutdown(context.Canceled)
			}
			require.Error(t, done.Err())
		})
	}
}
