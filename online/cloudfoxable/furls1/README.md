# CloudFoxable - Furls1

Challenge link: https://cloudfoxable.bishopfox.com/challenges#Furls%201-10

![](images/furls1-description.png)

## Using cloudfox

Cloudfox support us a command called **`endpoints`**:

```
cloudfox aws -p cloudfoxable endpoints
```

![](images/furls1-cloudfox-endpoints.png)

It will find all and give us all endpoints that are available. We can see there is endpoint with name **`furls1`** so let's browser with that url:

![](images/furls1-get-flag.png)

## Using aws-cli

The description gives us a hint that we will need to look at lambda function so let's list all function with **`lambda list-functions`**:

```
aws --profile cloudfoxable lambda list-functions
```

![](images/furls1-aws-cli-lambda-list-functions.png)

We can see there is a function called **`furls1`**. Now we want to get the url for that lambda function, we can run **`lambda get-function-url-config`**:

```
aws --profile cloudfoxable lambda get-function-url-config --function-name furls1
```

![](images/furls1-aws-cli-lambda-get-function-url-config.png)

Bingo, we got the URL, let's browse that URL to see what we got:

![](images/furls1-get-flag.png)

That URL gives us the flag haha!

