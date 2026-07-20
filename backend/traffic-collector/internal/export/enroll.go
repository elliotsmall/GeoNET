package export

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"
)

type Credential struct {
	HostID   string    `json:"host_id"`
	Token    string    `json:"token"`
	IssuedAt time.Time `json:"issued_at"`
}

func LoadCredential() (Credential, error) {
	var credential Credential
	file, err := os.Open("/var/lib/geonet/credential.json")
	if err != nil {
		if os.IsNotExist(err) {
			return credential, err
		}
		return credential, fmt.Errorf("error reading credential file: %v", err)
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&credential); err != nil {

		return credential, fmt.Errorf("error decoding json: %v", err)
	}

	return credential, nil
}

func SaveCredential(credential Credential) error {
	err := os.MkdirAll("/var/lib/geonet", 0700)
	if err != nil {
		return fmt.Errorf("creating directory: %v", err)
	}

	jsonData, err := json.MarshalIndent(credential, "", "    ")
	if err != nil {
		return fmt.Errorf("marshaling to JSON: %v", err)
	}

	err = os.WriteFile("/var/lib/geonet/credential.json", jsonData, 0600)
	if err != nil {
		return fmt.Errorf("writing to file: %v", err)
	}

	return nil
}

func Enroll() (Credential, error) {
	var credential Credential

	bootstrapToken := os.Getenv("BOOTSTRAP_KEY")
	if bootstrapToken == "" {
		return credential, fmt.Errorf("BOOTSTRAP_KEY NOT SET")
	}
	endpoint := os.Getenv("CONTROL_URL")
	if endpoint == "" {
		return credential, fmt.Errorf("CONTROL_URL NOT SET")
	}

	credential, err := RequestCredential(bootstrapToken, endpoint)
	if err != nil {
		return credential, fmt.Errorf("requesting credential: %v", err)
	}

	//Credential received, save to file
	err = SaveCredential(credential)
	if err != nil {
		return credential, fmt.Errorf("saving credential: %v", err)
	}

	return credential, err
}

func RequestCredential(bootstrapToken, endpoint string) (Credential, error) {
	var credential Credential

	url := endpoint + "/enroll"

	request, err := http.NewRequest(http.MethodPost, url, nil)
	if err != nil {
		return credential, err
	}
	request.Header.Set("Authorization", "Bearer "+bootstrapToken)
	request.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	response, err := client.Do(request)
	if err != nil {
		return credential, err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusCreated {
		return credential, fmt.Errorf("enrollment failed: %v", response.StatusCode)
	}

	if err := json.NewDecoder(response.Body).Decode(&credential); err != nil {
		return credential, err
	}

	return credential, nil
}
