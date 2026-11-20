package gateway

import (
	"bytes"
	"container/list"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"hash"
	"strings"
	"sync"
	"time"

	"github.com/ayatinene/ASGemini2API/internal/aicode/pb"
	"github.com/ayatinene/ASGemini2API/internal/chat"
	"google.golang.org/protobuf/proto"
)

const (
	historyTTL     = 2 * time.Hour
	historyEntries = 256
	historyLimit   = 16 << 20
	historyMaxTurn = 1 << 20
)

type turnKey = [sha256.Size]byte

type historyEntry struct {
	key     turnKey
	content []byte
	expires time.Time
}

type history struct {
	mu    sync.Mutex
	lru   list.List
	turns map[turnKey]*list.Element
	size  int
}

func newHistory() *history {
	return &history{turns: make(map[turnKey]*list.Element)}
}

// reset drops every cached turn. It is called when the active Google account
// changes so a conversation ID cannot restore content from the old account.
func (h *history) reset() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.lru.Init()
	h.turns = make(map[turnKey]*list.Element)
	h.size = 0
}

func (h *history) remove(e *list.Element) {
	entry := e.Value.(*historyEntry)
	delete(h.turns, entry.key)
	h.size -= len(entry.content)
	h.lru.Remove(e)
}

func (h *history) lookup(key turnKey) *pb.Content {
	h.mu.Lock()
	defer h.mu.Unlock()
	e := h.turns[key]
	if e == nil {
		return nil
	}
	entry := e.Value.(*historyEntry)
	if time.Now().After(entry.expires) {
		h.remove(e)
		return nil
	}
	h.lru.MoveToFront(e)
	if len(entry.content) == 0 {
		return nil
	}
	var result pb.Content
	if proto.Unmarshal(entry.content, &result) != nil {
		return nil
	}
	return &result
}

func (h *history) store(key turnKey, content *pb.Content) {
	if content == nil || proto.Size(content) > historyMaxTurn {
		return
	}
	blob, err := proto.MarshalOptions{Deterministic: true}.Marshal(content)
	if err != nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	now := time.Now()
	if e := h.turns[key]; e != nil {
		prior := e.Value.(*historyEntry)
		if now.Before(prior.expires) {
			if bytes.Equal(prior.content, blob) {
				h.lru.MoveToFront(e)
				return
			}
			// Never select an arbitrary history when two visible turns collide.
			blob = nil
		}
		h.remove(e)
	}
	h.turns[key] = h.lru.PushFront(&historyEntry{key: key, content: blob, expires: now.Add(historyTTL)})
	h.size += len(blob)
	for h.lru.Len() > historyEntries || h.size > historyLimit {
		h.remove(h.lru.Back())
	}
}

func addJSON(h hash.Hash, value any) {
	blob, _ := json.Marshal(value) // normalized request/response JSON data only
	var lenPrefix [8]byte
	binary.BigEndian.PutUint64(lenPrefix[:], uint64(len(blob)))
	h.Write(lenPrefix[:])
	h.Write(blob)
}

func visibleText(m chat.Message) any {
	switch content := m.Content.(type) {
	case nil:
		if m.Role == "assistant" {
			return ""
		}
	case []any:
		pieces := make([]string, 0, len(content))
		for _, item := range content {
			part, ok := item.(map[string]any)
			if !ok || part["type"] != "text" {
				return m.Content
			}
			value, ok := part["text"].(string)
			if !ok {
				return m.Content
			}
			pieces = append(pieces, value)
		}
		return visibleParts(m.Role, pieces)
	case []chat.ContentPart:
		pieces := make([]string, 0, len(content))
		for _, part := range content {
			if part.Type != "text" {
				return m.Content
			}
			pieces = append(pieces, part.Text)
		}
		return visibleParts(m.Role, pieces)
	}
	return m.Content
}

func visibleParts(role string, pieces []string) any {
	if role == "user" && len(pieces) != 1 {
		// Multiple text parts stay separate on the wire for user messages.
		return pieces
	}
	return strings.Join(pieces, "\n")
}

func addMessage(h hash.Hash, msg chat.Message) {
	calls := make([][3]any, 0, len(msg.ToolCalls))
	for _, call := range msg.ToolCalls {
		var args any
		d := json.NewDecoder(strings.NewReader(call.Function.Arguments))
		d.UseNumber()
		if !json.Valid([]byte(call.Function.Arguments)) || d.Decode(&args) != nil {
			args = call.Function.Arguments
		}
		calls = append(calls, [3]any{call.ID, call.Function.Name, args})
	}
	// The restore key must survive clients dropping nonstandard signature/Thinking fields.
	addJSON(h, []any{msg.Role, msg.Name, visibleText(msg), msg.ToolCallID, calls})
}

func keyFor(h hash.Hash) (key turnKey) {
	h.Sum(key[:0])
	return key
}

type historyView struct {
	owner    *history
	digest   hash.Hash
	prefixes map[int]turnKey
}

func (h *history) view(model, experience, user, conversation string, msgs []chat.Message) *historyView {
	digest := sha256.New()
	addJSON(digest, [4]string{model, experience, user, conversation})
	prefixes := make(map[int]turnKey)
	for i, msg := range msgs {
		addMessage(digest, msg)
		if msg.Role == "assistant" {
			prefixes[i] = keyFor(digest)
		}
	}
	return &historyView{owner: h, digest: digest, prefixes: prefixes}
}

func (v *historyView) restore(index int, _ chat.Message) *pb.Content {
	if key, ok := v.prefixes[index]; ok {
		return v.owner.lookup(key)
	}
	return nil
}

func (v *historyView) remember(msg chat.Message, content *pb.Content) {
	addMessage(v.digest, msg)
	v.owner.store(keyFor(v.digest), content)
}
