package export

import (
	"GeoNET/pkg/wire"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

type Exporter struct {
	EndpointURL string
	Credential  wire.Credential
	Client      *http.Client
}

func New(endpoint string, credential wire.Credential) *Exporter {
	return &Exporter{
		EndpointURL: endpoint,
		Credential:  credential,
		Client:      &http.Client{Timeout: 10 * time.Second},
	}
}

func (exporter *Exporter) Send(batch wire.FlowBatch) error {
	jsonData, err := json.Marshal(batch)
	if err != nil {
		return fmt.Errorf("marshaling batch: %v", err)
	}

	url := exporter.EndpointURL + "/ingest"

	request, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(jsonData))
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+exporter.Credential.Token)
	request.Header.Set("Content-Type", "application/json")

	response, err := exporter.Client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	switch response.StatusCode {
	case http.StatusAccepted:
		return nil
	case http.StatusForbidden, http.StatusUnauthorized:
		return fmt.Errorf("credential invalid")
	default:
		return fmt.Errorf("other http error: %v", response.StatusCode)
	}

}
