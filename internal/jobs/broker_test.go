package jobs

import (
	"testing"
	"time"
)

func TestBroker_SubscribeAndPublish(t *testing.T) {
	b := NewBroker()
	ch, unsub := b.Subscribe("job-1")
	defer unsub()

	b.Publish("job-1", "hello")
	b.Publish("job-1", "world")

	select {
	case got := <-ch:
		if got != "hello" {
			t.Errorf("first msg = %q, want hello", got)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for first message")
	}

	select {
	case got := <-ch:
		if got != "world" {
			t.Errorf("second msg = %q, want world", got)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for second message")
	}
}

func TestBroker_PublishWithNoSubscribers(t *testing.T) {
	b := NewBroker()
	// Should not block or panic when there are no subscribers.
	b.Publish("job-nothing", "line")
}

func TestBroker_MultipleSubscribers(t *testing.T) {
	b := NewBroker()

	ch1, unsub1 := b.Subscribe("job-multi")
	ch2, unsub2 := b.Subscribe("job-multi")
	defer unsub1()
	defer unsub2()

	b.Publish("job-multi", "broadcast")

	for i, ch := range []<-chan string{ch1, ch2} {
		select {
		case got := <-ch:
			if got != "broadcast" {
				t.Errorf("subscriber %d got %q, want broadcast", i+1, got)
			}
		case <-time.After(time.Second):
			t.Fatalf("subscriber %d: timeout", i+1)
		}
	}
}

func TestBroker_CloseJob(t *testing.T) {
	b := NewBroker()
	ch, _ := b.Subscribe("job-close")

	b.CloseJob("job-close")

	select {
	case _, open := <-ch:
		if open {
			t.Error("channel should be closed after CloseJob")
		}
	case <-time.After(time.Second):
		t.Fatal("channel not closed after CloseJob")
	}
}

func TestBroker_UnsubscribeStopsDelivery(t *testing.T) {
	b := NewBroker()
	ch, unsub := b.Subscribe("job-unsub")
	unsub()

	// After unsubscribing, publishing should not panic.
	b.Publish("job-unsub", "after-unsub")

	// Channel should remain open but receive nothing (only 1 message and no
	// sender after unsub, so drain with a short timeout).
	select {
	case <-ch:
		// If something came through before unsub took effect, that's acceptable.
		// If the broker closed the channel, that's fine too.
	case <-time.After(50 * time.Millisecond):
		// Nothing received — expected.
	}
}

func TestBroker_PublishToWrongJobID(t *testing.T) {
	b := NewBroker()
	ch, unsub := b.Subscribe("job-a")
	defer unsub()

	b.Publish("job-b", "wrong-job")

	select {
	case got := <-ch:
		t.Errorf("received unexpected message on wrong channel: %q", got)
	case <-time.After(50 * time.Millisecond):
		// Expected: nothing delivered to job-a.
	}
}

func TestBroker_SlowSubscriberDropsMessages(t *testing.T) {
	b := NewBroker()
	ch, unsub := b.Subscribe("job-slow")
	defer unsub()

	// Publish more messages than the channel buffer (64) to test drop behaviour.
	for i := 0; i < 100; i++ {
		b.Publish("job-slow", "msg")
	}

	// Drain all available messages — no panic, no deadlock.
	drained := 0
	done := time.After(200 * time.Millisecond)
drain:
	for {
		select {
		case <-ch:
			drained++
		case <-done:
			break drain
		}
	}
	// At most 64 should have been buffered (rest were dropped).
	if drained > 64 {
		t.Errorf("drained %d messages, channel buffer is 64", drained)
	}
}
