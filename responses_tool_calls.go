package main

type responsesToolCalls struct {
	next      int
	indices   map[string]int
	aliases   map[string]string
	argDeltas map[string]bool
}

func (t *responsesToolCalls) register(itemID, callID string) int {
	if t.indices == nil {
		t.indices = map[string]int{}
		t.aliases = map[string]string{}
	}
	if callID == "" {
		callID = itemID
	}
	if itemID != "" && callID != "" {
		t.aliases[itemID] = callID
	}
	if callID != "" {
		if index, ok := t.indices[callID]; ok {
			return index
		}
	}
	index := t.next
	t.next++
	if callID != "" {
		t.indices[callID] = index
	}
	return index
}

func (t *responsesToolCalls) resolve(callID string) string {
	if resolved := t.aliases[callID]; resolved != "" {
		return resolved
	}
	return callID
}

func (t *responsesToolCalls) eventID(event map[string]any) string {
	callID, _ := event["call_id"].(string)
	if callID == "" {
		callID, _ = event["item_id"].(string)
	}
	return t.resolve(callID)
}

func (t *responsesToolCalls) itemID(item map[string]any) string {
	callID, _ := item["call_id"].(string)
	if callID == "" {
		callID, _ = item["id"].(string)
	}
	return t.resolve(callID)
}

func (t *responsesToolCalls) noteDelta(callID string) {
	if callID == "" {
		return
	}
	if t.argDeltas == nil {
		t.argDeltas = map[string]bool{}
	}
	t.argDeltas[callID] = true
}
