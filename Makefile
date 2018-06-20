all:
	GOOS=linux  GOARCH=amd64 go build -o x509ck-linux-amd64
	GOOS=darwin GOARCH=amd64 go build -o x509ck-darwin-amd64
