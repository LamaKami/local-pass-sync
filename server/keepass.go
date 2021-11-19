package server

import (
	"bytes"
	"github.com/tobischo/gokeepasslib"
	"log"
	"os"
	"time"
)


func mkValue(key string, value string) gokeepasslib.ValueData {
	return gokeepasslib.ValueData{Key: key, Value: gokeepasslib.V{Content: value}}
}

func mkProtectedValue(key string, value string) gokeepasslib.ValueData {
	return gokeepasslib.ValueData{
		Key:   key,
		Value: gokeepasslib.V{Content: value, Protected: true},
	}
}

func unlockDatabase(keepassFile []byte, password string) *gokeepasslib.Database{
	reader := bytes.NewReader(keepassFile)

	db := gokeepasslib.NewDatabase()
	db.Credentials = gokeepasslib.NewPasswordCredentials(password)
	_ = gokeepasslib.NewDecoder(reader).Decode(db)

	err := db.UnlockProtectedEntries()
	if err != nil{
		log.Fatal(err)
	}
	return db
}

func saveAndLockDatabase(path string, db *gokeepasslib.Database){
	file, err := os.Create(path)
	if err != nil{
		log.Fatal(err)
	}

	err = db.LockProtectedEntries()
	if err != nil {
		log.Println(err)
	}

	keepassEncoder := gokeepasslib.NewEncoder(file)
	if err := keepassEncoder.Encode(db); err != nil {
		panic(err)
	}

	log.Printf("Wrote kdbx file: %s", path)
}

func LockDatabase(db *gokeepasslib.Database){
	err := db.LockProtectedEntries()
	if err != nil {
		log.Println(err)
	}
}

func iterateGroup(group []gokeepasslib.Group, db *gokeepasslib.Database, m map[gokeepasslib.UUID] gokeepasslib.Entry) map[gokeepasslib.UUID] gokeepasslib.Entry{
	for _, element := range group{
		for _, entry := range element.Entries{
			m[entry.UUID] = entry
		}
		iterateGroup(element.Groups, db, m)
	}
	return m
}

func getMapForAllEntries(db *gokeepasslib.Database) map[gokeepasslib.UUID] gokeepasslib.Entry{
	m := make(map[gokeepasslib.UUID]gokeepasslib.Entry)
	return iterateGroup(db.Content.Root.Groups, db, m)
}

func searchUUIDs(clientGroup []gokeepasslib.Group, serverDb *gokeepasslib.Database, serverEntries map[gokeepasslib.UUID] gokeepasslib.Entry, fileModified *bool){
	var keys = []string{"Notes", "Title", "URL", "Username", "UserName"}
	for _, clientElement := range clientGroup{
		for _, clientEntry := range clientElement.Entries{
			// checks if the entries from the client are in the server file
			if serverEntry, ok := serverEntries[clientEntry.UUID]; ok {
				if time.Time(*clientEntry.Times.LastModificationTime).After(time.Time(*serverEntry.Times.LastModificationTime)) {
					//change ServerEntry
					additionalKeys := append(keys, "Password")

					for _, key := range additionalKeys{
						if index := clientEntry.GetIndex(key); index != -1 {
							serverEntry.Values[index].Value.Content = clientEntry.Values[index].Value.Content
						}
					}
					*fileModified = true
				} else if time.Time(*serverEntry.Times.LastModificationTime).After(time.Time(*clientEntry.Times.LastModificationTime))  {
					// we dont need to change something if a newer version of an entry is on the server because we are returning the server file
					// but we have to know that the client needs a new version
					*fileModified = true
				}
			} else {
				// add the entry to the server file if it doesnt exits
				entry := gokeepasslib.NewEntry()
				for _, key := range keys{
					if index := clientEntry.GetIndex(key); index != -1 {
						entry.Values = append(entry.Values, mkValue(key, clientEntry.Values[index].Value.Content))
					}
				}

				index := clientEntry.GetIndex("Password")
				entry.Values = append(entry.Values, mkProtectedValue("Password", clientEntry.Values[index].Value.Content))

				serverDb.Content.Root.Groups[0].Entries = append(serverDb.Content.Root.Groups[0].Entries, entry)
				*fileModified = true
			}
		}
		searchUUIDs(clientElement.Groups, serverDb, serverEntries, fileModified)
	}
}

func compareDatabases(clientDb *gokeepasslib.Database, serverDb *gokeepasslib.Database) bool{
	// right now we are only adding and changing entries
	serverEntries := getMapForAllEntries(serverDb)
	fileModified := false

	searchUUIDs(clientDb.Content.Root.Groups, serverDb, serverEntries, &fileModified)

	return fileModified
}

