package widget

type Widget struct {
	Widget string `json:"widget"`
	Object string `json:"object"`
}

type ActionRes struct {
	Type  string `json:"type"`
	Name  Name   `json:"name"`
	Query bool   `json:"query"`
}

type Name struct {
	ENG string `json:"eng"`
	LNG string `json:"lng"`
}
