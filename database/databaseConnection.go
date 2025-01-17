package database

import (
	"fmt"
	"context"
	"log"
	"time"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func DBInstance() *mongo.Client {
	
	MongoDb := "mongodb://localhost:27017"
	fmt.Print(MongoDb)

	client, err := mongo.NewClient(options.Client().ApplyURI(MongoDb))

	if err!=nil {
		log.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()

	err = client.Connect(ctx) 

	if err!=nil {
		log.Fatal(err)
	}
	fmt.Println("Connected to MongoDB")

	return client 
}

var Client *mongo.Client = DBInstance()

func OpenCollection(client *mongo.Client, collectionName string) *mongo.Collection {
	var collection *mongo.Collection = client.Database("restaurant").Collection(collectionName)

	return collection
}