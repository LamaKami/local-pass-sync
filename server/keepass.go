package server

import (
	"bytes"
	"github.com/tobischo/gokeepasslib"
	"log"
	"os"
	"time"
)

// creates a new key-value pair for an entry
func mkValue(key string, value string) gokeepasslib.ValueData {
	return gokeepasslib.ValueData{Key: key, Value: gokeepasslib.V{Content: value}}
}

// creates a new key-value pair for an entry which is protected
// this should be used for passwords
func mkProtectedValue(key string, value string) gokeepasslib.ValueData {
	return gokeepasslib.ValueData{
		Key:   key,
		Value: gokeepasslib.V{Content: value, Protected: true},
	}
}

// returns the readable database file for a keepass file
func unlockDatabase(keepassFile []byte, password string) (*gokeepasslib.Database, error){
	reader := bytes.NewReader(keepassFile)

	db := gokeepasslib.NewDatabase()
	db.Credentials = gokeepasslib.NewPasswordCredentials(password)

	if err := gokeepasslib.NewDecoder(reader).Decode(db); err != nil{
		return nil, err
	}

	if err := db.UnlockProtectedEntries(); err != nil{
		return nil, err
	}

	return db, nil
}

// locks the db and saves the keepass file on the given path
func saveAndLockDatabase(path string, db *gokeepasslib.Database) error{
	file, err := os.Create(path)
	if err != nil{
		return err
	}

	if err := db.LockProtectedEntries(); err != nil {
		return err
	}

	keepassEncoder := gokeepasslib.NewEncoder(file)
	if err := keepassEncoder.Encode(db); err != nil {
		return err
	}

	log.Printf("Wrote kdbx file: %s", path)
	return nil
}

// LockDatabase only locks the file again
func LockDatabase(db *gokeepasslib.Database){
	if err := db.LockProtectedEntries(); err != nil {
		log.Println(err)
	}
}

// compares two dbs and tracks if there is a difference
// we are only changing the server file and keeping the client file untouched
func compareDatabases(clientDb *gokeepasslib.Database, serverDb *gokeepasslib.Database) bool{
	// right now we are only adding and changing entries and not deleting anything
	serverEntries := getMapForAllEntries(serverDb)
	fileModified := false

	compareClientAndServerEntries(clientDb.Content.Root.Groups, serverDb, serverEntries, &fileModified)

	return fileModified
}

// returns a map of all entries in the db
func getMapForAllEntries(db *gokeepasslib.Database) map[gokeepasslib.UUID] gokeepasslib.Entry{
	m := make(map[gokeepasslib.UUID]gokeepasslib.Entry)
	iterateGroup(db.Content.Root.Groups, db, m)
	return m
}

// loops through all groups and sub-groups recursively and gathers all entries
func iterateGroup(group []gokeepasslib.Group, db *gokeepasslib.Database, m map[gokeepasslib.UUID] gokeepasslib.Entry){
	for _, element := range group{
		for _, entry := range element.Entries{
			m[entry.UUID] = entry
		}
		iterateGroup(element.Groups, db, m)
	}
}

//  loops through all groups and sub-groups recursively and compares the entries with a given map
func compareClientAndServerEntries(clientGroup []gokeepasslib.Group, serverDb *gokeepasslib.Database, serverEntries map[gokeepasslib.UUID] gokeepasslib.Entry, fileModified *bool){
	var keys = []string{"Notes", "Title", "URL", "Username", "UserName"}
	for _, clientElement := range clientGroup{
		for _, clientEntry := range clientElement.Entries{
			// checks if the entries from the client are in the server file
			if serverEntry, ok := serverEntries[clientEntry.UUID]; ok {
				compareLastModificationTime(&serverEntry, clientEntry, fileModified, keys)
			} else {
				// add the entry to the server file if it doesnt exits
				createNewEntry(clientEntry, serverDb, keys, fileModified)
			}
		}
		compareClientAndServerEntries(clientElement.Groups, serverDb, serverEntries, fileModified)
	}
}

// changes the server entry if the client has a newer version of this entry
func compareLastModificationTime(serverEntry *gokeepasslib.Entry, clientEntry gokeepasslib.Entry, fileModified *bool, keys []string){
	if time.Time(*clientEntry.Times.LastModificationTime).After(time.Time(*serverEntry.Times.LastModificationTime)) {
		// change ServerEntry
		additionalKeys := append(keys, "Password")

		// looping through the keys and set the client values on the server entry values
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
}

// creates a new gokeepasslib entry with the client entry values and writes it to the given server db
func createNewEntry(clientEntry gokeepasslib.Entry, serverDb *gokeepasslib.Database, keys []string, fileModified *bool){
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