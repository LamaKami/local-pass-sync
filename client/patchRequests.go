package client

import (
	"io"
	c "local-pass-sync/config"
	"log"
)

// HandlingPatchRequest uses the config to create the request and also handles the server response
func HandlingPatchRequest(cfg c.Config){
	body, err := createFileRequestBody(cfg)
	if err != nil{
		log.Fatal("While creating the request body with the kdbx file and the keys," +
			" the following error occurred: ", err)
	}

	req, err := createRequest(cfg, body, "PATCH", "/keepass")
	if err != nil{
		log.Fatal("While creating the patch request, the following error occurred: ", err)
	}
	resp, err := createTlsClient(cfg).Do(req)
	if err != nil {
		log.Fatal(err)
	}

	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Fatal("While closing the request body, the following error occurred: ",err)
		}
	}(resp.Body)

	if err, changed := handleResponse(cfg, resp); err != nil{
		log.Fatal("While handling the server response, the following error occurred: ", err)
	} else if !changed{
		return
	}

	log.Println("File was successfully changed on the client")
}
