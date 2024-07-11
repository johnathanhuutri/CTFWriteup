# CloudFoxable - Needles

Challenge link: https://cloudfoxable.bishopfox.com/challenges#Needles-20

![](images/needles-description.png)

Let's create new profile for **`ramos`**:

```
[profile ramos]
region = us-west-2
role_arn = arn:aws:iam::<ACCOUNTID>:role/ramos
source_profile = cloudfoxable
```

## Using cloudfox

Just simply scan all permission of `ramos`:

```
cloudfox aws -p cloudfoxable permissions --principal ramos
```

![](images/needles-cloudfox-permission-ramos.png)

We can see a lot of policies but I see the `cloudformation` has more policies then other so let's just scan for `cloudformation`:

```
cloudfox aws -p cloudfoxable cloudformation
```

![](images/needles-cloudfox-cloudformation.png)

I can see there is only one stack `cloudformationStack` but the main thing I want to focus is the loot, let's read that file:

![](images/needles-cloudfox-get-flag.png)

And we get the flag!

## Using aws-cli

Same as using cloudfox, we will need to check what policy do we have on `ramos`:

```
aws --profile cloudfoxable iam list-attached-role-policies --role-name ramos
```

![](images/needles-aws-cli-list-attached-role-policies.png)

Let's check each policy top down. First is CloudFormation, let's try to list-stacks to see if there are somethings interesting:

```
aws --profile ramos cloudformation list-stacks
```

![](images/needles-aws-cli-cloudformation-list-stacks.png)

There is 1 stack only, let's check its template:

```
aws --profile ramos cloudformation get-template --stack-name cloudformationStack
```

![](images/needles-aws-cli-get-flag.png)

Bingo!
