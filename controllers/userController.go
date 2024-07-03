package controller

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"res-mgt/database"
	"res-mgt/helper"
	"res-mgt/models"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
)

var userCollection *mongo.Collection = database.OpenCollection(database.Client, "user")

func GetUsers() gin.HandlerFunc {
	return func (c *gin.Context) {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)

		recordPerPage, err :=  strconv.Atoi(c.Query("recordPerPage"))

		if err!=nil || recordPerPage < 1 { 
			recordPerPage = 10
		}

		page, err1 := strconv.Atoi(c.Query("page"))

		if err1!=nil || page < 1 {
			page = 1
		}

		startIndex := (page-1) * recordPerPage

		startIndex, err = strconv.Atoi(c.Query("startIndex"))

		matchStage := bson.D{{"$match", bson.D{{}}}}
		projectStage := bson.D{{
			"$project", bson.D{
				{"_id", 0},
				{"total_count", 1},
				{"user_items", bson.D{{"$slice", []interface{}{"$data", startIndex, recordPerPage} }} },
			},
		}}

		result, err := userCollection.Aggregate(ctx, mongo.Pipeline{
			matchStage, projectStage,
		})

		defer cancel()

		if err!=nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "An error occurred while listing user items"})
		}

		var allUsers []bson.M
		
		if err= result.All(ctx, &allUsers); err!=nil {
			log.Fatal(err)
		}
		c.JSON(http.StatusOK, allUsers[0])
	}
}

func GetUser() gin.HandlerFunc {
	return func (c *gin.Context) {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
		userId := c.Param("user_id")

		var user models.User

		err := userCollection.FindOne(ctx, bson.M{"user_id": userId}).Decode(&user)

		defer cancel()

		if err!=nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "An error occurred while listing the user item"})
			return 
		}

		c.JSON(http.StatusOK, user)
	}
}

func SignUp() gin.HandlerFunc {
	return func (c *gin.Context) {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
		var user models.User

		//Convert the JSON data coming from the Postman to something Golang understands
		if err := c.BindJSON(&user); err!=nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		//Validate the data based on user struct
		validationErr := validate.Struct(user) 
		
		if validationErr!=nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": validationErr.Error()})
			return
		}
		//Check if the email has already been used by another user
		count, err := userCollection.CountDocuments(ctx, bson.M{"email": user.Email})
		defer cancel()
		if err!=nil {
			log.Panic(err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "An error occurred while checking for the email"})
		}
		//Hash password
		password := HashPassword(*user.Password)
		user.Password = &password
		//Check if the phone number has already been used by another user
		count, err = userCollection.CountDocuments(ctx, bson.M{"phone": user.Phone})
		defer cancel()
		if err!=nil {
			log.Panic(err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "An error occurred while checking for the phone number"})
			return
		}

		if count > 0 {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "This email or phone number already exist"})
			return
		}


		//create some extra details - created_at, updated_at, ID
		user.Created_at, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339)) 
		user.Updated_at, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339)) 
		user.ID = primitive.NewObjectID()
		user.User_id = user.ID.Hex()
		//generate a token and refresh the token (generate all tokens function from helper)
		token, refreshToken, _ := helper.GenerateAllTokens(*user.Email, *user.First_name, *user.Last_name, user.User_id)
		user.Token = &token
		user.Refresh_token = &refreshToken
		//if all ok then you can insert this user into the userCollection

		resultInsertionNumber, insertErr := userCollection.InsertOne(ctx, user)

		if insertErr!=nil {
			msg := fmt.Sprintf("User item was not created")
			c.JSON(http.StatusInternalServerError, gin.H{"error": msg})
			return
		}
		defer cancel()
		//Return statusOK and send the result back
		c.JSON(http.StatusOK, resultInsertionNumber)
	}	
}

func Login() gin.HandlerFunc {
	return func (c *gin.Context) {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
		var user models.User
		var foundUser models.User

		//Convert the login data from postman (in JSON) to golang readable format
		if err := c.BindJSON(&user); err!=nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}


		//Find the user with that email and see if that user exists
		err := userCollection.FindOne(ctx, bson.M{"email": user.Email}).Decode(&foundUser)
		defer cancel()

		if err!= nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "User not found"})
			return
		}
		//Then verify the password
		passwordIsValid, msg := VerifyPassword(*user.Password, *foundUser.Password)
		defer cancel()

		if passwordIsValid!=true {
			c.JSON(http.StatusInternalServerError, gin.H{"error": msg})
			return
		}
	
		//If all goes well, then you'll generate tokens
		token, refreshToken, _ := helper.GenerateAllTokens(*foundUser.Email, *foundUser.First_name, *foundUser.Last_name, foundUser.User_id)
		//Update tokens - token and refresh token
		helper.UpdateAllTokens(token, refreshToken, foundUser.User_id)
		//Return statusOK
		c.JSON(http.StatusOK, foundUser)
	}
}

func HashPassword(password string) string {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)	
	if err!=nil {
		log.Panic(err)
	}

	return string(bytes)

}

func VerifyPassword(userPassword, providedPassword string) (bool, string) {
	err := bcrypt.CompareHashAndPassword([]byte(providedPassword), []byte(userPassword))
	check := true 
	msg := ""

	if err!=nil {
		msg = fmt.Sprintf("Login or password is incorrect")
		check = false
	}

	return check, msg 
} 