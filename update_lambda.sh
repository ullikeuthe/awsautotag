zip -u autotag.zip autotag.py
aws lambda update-function-code --function-name TestLambda --zip-file fileb://autotag.zip
aws s3 cp autotag.zip s3://ullikeuthe12345/autotag.zip
