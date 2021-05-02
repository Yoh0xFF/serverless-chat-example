import json
import logging
from datetime import datetime

import boto3
import jwt

logger = logging.getLogger("handler_logger")
logger.setLevel(logging.DEBUG)

dynamodb = boto3.resource("dynamodb")

CHAT_CONNECTIONS_TABLE = "serverless-chat_Connections"
CHAT_MESSAGES_TABLE = "serverless-chat_Messages"


def default_message(event, context):
    """
    Send back error when unrecognized WebSocket action is received.
    """
    logger.info("Unrecognized WevSocket action received")
    return _get_response(400, "Unrecognized WebSocket action.")


def ping(event, context):
    """
    Sanity check endpoint that echoes back to the sender
    """
    logger.info(f"Ping requested, ts: {datetime.utcnow().isoformat()}")
    return _get_response(200, "Pong.")


def connection_manager(event, context):
    """
    Handles connecting and disconnecting for the WebSocket.
    """
    request_context = event["requestContext"]
    connection_id = request_context.get("connectionId")
    event_type = request_context.get("eventType")
    token = event.get("queryStringParameters", {}).get("token")

    if event_type == "CONNECT":
        logger.info(f"Connect requested {connection_id}")

        # Ensure token was provided
        if not token:
            logger.error("Failed: token query parameter not provided.")
            return _get_response(400, "token query parameter not provided.")

        # Verify the token
        try:
            payload = jwt.decode(token, "TOP_SECRET", algorithms="HS256")
            logger.info("Verified JWT for '{}'".format(payload.get("username")))
        except:
            logger.error("Failed: Token verification failed.")
            return _get_response(400, "Token verification failed.")

        # Add connection id to the database
        table = dynamodb.Table(CHAT_CONNECTIONS_TABLE)
        table.put_item(Item={"ConnectionId": connection_id})

        return _get_response(200, "Connected successfully!")
    elif event_type == "DISCONNECT":
        logger.info(f"Disconnect requested {connection_id}")

        # Remove connection id from the database
        table = dynamodb.Table(CHAT_CONNECTIONS_TABLE)
        table.delete_item(Key={"ConnectionId": connection_id})

        return _get_response(200, "Disconnected successfully!")
    else:
        logger.error("Connection manager received unrecognized event type")
        return _get_response(500, "Unrecognized event type!")


def send_message(event, context):
    """
    When a message is sent on the socket, forward it to all connections
    """
    logger.info("Message sent on WebSocket")

    # Ensure all requited fields were provided
    body = _get_body(event)
    for attr in ["token", "content"]:
        if attr not in body:
            logger.error(f"Failed: field '{attr}' not in message dict!")
            return _get_response(400, f"Failed: field '{attr}' not in message dict!")

    # Verify the token
    try:
        payload = jwt.decode(body["token"], "TOP_SECRET", algorithms="HS256")
        username = payload.get("username")
        logger.info("Verified JWT for '{}'".format(username))
    except:
        logger.error("Failed: Token verification failed.")
        return _get_response(400, "Token verification failed.")

    # Get the next message index
    table = dynamodb.Table(CHAT_MESSAGES_TABLE)

    response = table.query(
        KeyConditionExpression="Room = :room",
        ExpressionAttributeValues={":room": "general"},
        Limit=1, ScanIndexForward=False
    )
    items = response.get("Items", [])
    index = items[0]["Index"] + 1 if items else 0

    # Add new message to the database
    content = body["content"]
    table.put_item(Item={
        "Room": "general",
        "Index": index,
        "Timestamp": datetime.utcnow().isoformat(),
        "Username": username,
        "Content": content
    })

    # Get all current connections
    table = dynamodb.Table(CHAT_CONNECTIONS_TABLE)
    response = table.scan(ProjectionExpression="ConnectionId")
    items = response.get("Items", [])
    connection_ids = [x["ConnectionId"] for x in items if "ConnectionId" in x]

    # Send the message data to all connections
    message = {"username": username, "content": content}
    logger.info(f"Broadcasting message: {message}.")
    data = {"messages": [message]}
    for connection_id in connection_ids:
        _send_to_connection(connection_id, data, event)

    return _get_response(200, "Message sent to all connections.")


def get_recent_messages(event, context):
    """Return the 10 most recent chat messages"""
    logger.info("Retrieving most recent messages.")
    request_context = event["requestContext"]
    connection_id = request_context.get("connectionId")

    # Get the 10 most recent messages
    table = dynamodb.Table(CHAT_MESSAGES_TABLE)
    response = table.query(
        KeyConditionExpression="Room = :room",
        ExpressionAttributeValues={":room": "general"},
        Limit=10, ScanIndexForward=False
    )
    items = response.get("Items", [])

    # Extract the relevant data and order chronologically
    messages = [{"username": x["Username"], "content": x["Content"]} for x in items]
    messages.reverse()

    # Send them to the client who asked for it
    data = {"messages": messages}
    _send_to_connection(connection_id, data, event)

    return _get_response(200, "Sent recent messages")


def _send_to_connection(connection_id, data, event):
    request_context = event["requestContext"]

    gateway_api = boto3.client(
        "apigatewaymanagementapi",
        endpoint_url=f"https://{request_context['domainName']}/{request_context['stage']}"
    )

    return gateway_api.post_to_connection(
        ConnectionId=connection_id,
        Data=json.dumps(data).encode("utf-8")
    )


def _get_body(event):
    try:
        return json.loads(event.get("body", "{}"))
    except:
        logger.exception("Event body could not be JSON decoded")
        return {}


def _get_response(status_code, body):
    if not isinstance(body, str):
        body = json.dumps(body)
    return {"statusCode": status_code, "body": body}
