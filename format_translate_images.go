package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"strings"
	"time"
)

func imagesGenerationCount(body []byte) int {
	var req map[string]any
	if err := json.Unmarshal(body, &req); err != nil {
		return 1
	}
	n := int(toInt64(req["n"]))
	if n < 1 {
		return 1
	}
	return n
}

func setImagesGenerationCount(body []byte, n int) []byte {
	var req map[string]any
	if err := json.Unmarshal(body, &req); err != nil {
		return body
	}
	req["n"] = n
	out, err := json.Marshal(req)
	if err != nil {
		return body
	}
	return out
}

func translateImagesGenerationToResponses(body []byte) ([]byte, string, error) {
	var req map[string]any
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, "", fmt.Errorf("parse image generation request: %w", err)
	}
	prompt, _ := req["prompt"].(string)
	prompt = strings.TrimSpace(prompt)
	if prompt == "" {
		return nil, "", errors.New("prompt is required")
	}
	if n := toInt64(req["n"]); n > 1 {
		return nil, "", errors.New("internal fanout required for n > 1")
	}
	out, responseFormat, err := buildImagesResponsesRequest(req, []any{map[string]any{"type": "input_text", "text": prompt}})
	return out, responseFormat, err
}

func buildImagesResponsesRequest(req map[string]any, content []any) ([]byte, string, error) {
	model, _ := req["model"].(string)
	model = strings.TrimSpace(model)
	if model == "" || strings.HasPrefix(strings.ToLower(model), "gpt-image") || strings.HasPrefix(strings.ToLower(model), "dall-e") {
		model = "gpt-5.4-mini"
	}
	outputFormat, _ := req["output_format"].(string)
	if outputFormat == "" {
		outputFormat = "png"
	}
	if outputFormat != "png" && outputFormat != "jpeg" && outputFormat != "webp" {
		return nil, "", errors.New("output_format must be png, jpeg, or webp")
	}
	responseFormat, _ := req["response_format"].(string)
	if responseFormat == "" {
		responseFormat = "b64_json"
	}
	if responseFormat != "b64_json" && responseFormat != "url" {
		return nil, "", errors.New("response_format must be b64_json or url")
	}

	tool := map[string]any{"type": "image_generation", "output_format": outputFormat}
	for _, key := range []string{"size", "background", "moderation", "partial_images", "output_compression"} {
		if v, ok := req[key]; ok {
			tool[key] = v
		}
	}

	instructions := "Generate the requested image with the image_generation tool. Do not answer with text unless the image tool fails."
	out := map[string]any{
		"model":        model,
		"instructions": instructions,
		"input": []any{
			map[string]any{
				"type":    "message",
				"role":    "user",
				"content": content,
			},
		},
		"tools": []any{tool},
		"tool_choice": map[string]any{
			"type": "image_generation",
		},
		"stream": true,
		"store":  false,
	}
	rewritten, err := json.Marshal(out)
	if err != nil {
		return nil, "", err
	}
	return rewritten, responseFormat, nil
}

func translateImagesEditToResponses(body []byte, contentType string) ([]byte, string, error) {
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil || !strings.HasPrefix(mediaType, "multipart/") {
		return nil, "", errors.New("image edits must use multipart/form-data")
	}
	boundary := params["boundary"]
	if boundary == "" {
		return nil, "", errors.New("multipart boundary is required")
	}
	form, err := multipart.NewReader(bytes.NewReader(body), boundary).ReadForm(80 * 1024 * 1024)
	if err != nil {
		return nil, "", fmt.Errorf("parse image edit form: %w", err)
	}
	defer form.RemoveAll()
	req := map[string]any{}
	for key, values := range form.Value {
		if len(values) == 0 {
			continue
		}
		req[key] = values[len(values)-1]
	}
	prompt := strings.TrimSpace(firstFormValue(form, "prompt"))
	if prompt == "" {
		return nil, "", errors.New("prompt is required")
	}
	if n := toInt64(req["n"]); n > 1 {
		return nil, "", errors.New("internal fanout required for n > 1")
	}
	content := []any{map[string]any{"type": "input_text", "text": prompt}}
	for _, field := range []string{"image", "mask"} {
		for _, fh := range form.File[field] {
			imageURL, err := multipartImageDataURL(fh)
			if err != nil {
				return nil, "", err
			}
			content = append(content, map[string]any{"type": "input_image", "image_url": imageURL})
		}
	}
	if len(content) == 1 {
		return nil, "", errors.New("image is required")
	}
	out, responseFormat, err := buildImagesResponsesRequest(req, content)
	return out, responseFormat, err
}

func firstFormValue(form *multipart.Form, key string) string {
	values := form.Value[key]
	if len(values) == 0 {
		return ""
	}
	return values[len(values)-1]
}

func multipartImageDataURL(fh *multipart.FileHeader) (string, error) {
	file, err := fh.Open()
	if err != nil {
		return "", err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 40*1024*1024+1))
	if err != nil {
		return "", err
	}
	if len(data) > 40*1024*1024 {
		return "", errors.New("image file exceeds 40MB")
	}
	ct := fh.Header.Get("Content-Type")
	if ct == "" || ct == "application/octet-stream" {
		ct = "image/png"
	}
	return "data:" + ct + ";base64," + base64.StdEncoding.EncodeToString(data), nil
}

func appendImagesGenerationData(dst []any, body []byte, responseFormat string) ([]any, int64, error) {
	var resp map[string]any
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, 0, fmt.Errorf("parse images response: %w", err)
	}
	created := toInt64(resp["created"])
	data, _ := resp["data"].([]any)
	for _, entry := range data {
		if m, ok := entry.(map[string]any); ok {
			dst = append(dst, m)
		}
	}
	return dst, created, nil
}

func translateResponsesToImagesGeneration(body []byte, responseFormat string) ([]byte, error) {
	var resp map[string]any
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parse responses image response: %w", err)
	}
	output, _ := resp["output"].([]any)
	var result string
	var revisedPrompt string
	for _, raw := range output {
		item, _ := raw.(map[string]any)
		if item == nil {
			continue
		}
		if typ, _ := item["type"].(string); typ != "image_generation_call" {
			continue
		}
		if s, _ := item["result"].(string); s != "" {
			result = s
		}
		if s, _ := item["revised_prompt"].(string); s != "" {
			revisedPrompt = s
		}
	}
	if result == "" {
		return nil, errors.New("Codex image_generation did not return image bytes")
	}
	entry := map[string]any{}
	if responseFormat == "url" {
		entry["url"] = "data:image/png;base64," + result
	} else {
		entry["b64_json"] = result
	}
	if revisedPrompt != "" {
		entry["revised_prompt"] = revisedPrompt
	}
	created := toInt64(resp["created_at"])
	if created == 0 {
		created = time.Now().Unix()
	}
	out := map[string]any{
		"created": created,
		"data":    []any{entry},
	}
	return json.Marshal(out)
}
