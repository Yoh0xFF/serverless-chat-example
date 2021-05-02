import boto3
import json
import logging
import time

from datetime import datetime


logger = logging.getLogger("handler_logger")
logger.setLevel(logging.DEBUG)


dynamodb = boto3.resource("dynamodb")


def hello(event, context):
    body = {
        "message": "Go Serverless v1.0! Your function executed successfully!",
        "input": event
    }

    response = {
        "statusCode": 200,
        "body": json.dumps(body)
    }

    return response


def ping(event, context):
    global dynamodb

    body = {
        "message": f"Hola Amigo, pong - {datetime.utcnow()}!",
        "input": event
    }

    logger.info(f"Ping requested, ts: {datetime.utcnow()}")

    table = dynamodb.Table("serverless-chat_Messages")
    table.put_item(
        Item={
            "Room": "general",
            "Index": 0,
            "Timestamp": datetime.utcnow(),
            "Username": "ping-user",
            "Content": "Ping!"
        }
    )

    response = {
        "statusCode": 200,
        "body": json.dumps(body)
    }

    return response
