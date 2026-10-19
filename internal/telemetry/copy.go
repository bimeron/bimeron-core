package telemetry

import "io"

type countingWriter struct {
	writer io.Writer
	count  func(int64)
}

func (w countingWriter) Write(p []byte) (int, error) {
	n, err := w.writer.Write(p)
	if n > 0 {
		w.count(int64(n))
	}
	return n, err
}

// Count the bytes accepted by the destination before the stream finishes.
// The wrapper intentionally exposes only Write, preventing ReaderFrom fast paths
// from bypassing accounting. Source WriterTo still writes through this wrapper.
func (c *Counters) CopyUp(dst io.Writer, src io.Reader) (int64, error) {
	return io.Copy(countingWriter{dst, c.Sent}, src)
}
func (c *Counters) CopyDown(dst io.Writer, src io.Reader) (int64, error) {
	return io.Copy(countingWriter{dst, c.Received}, src)
}
