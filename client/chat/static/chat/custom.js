var socket;
var username = "client-" + Math.floor(Math.random() * 10000);

// Connect to the WebSocket and setup listeners
function setupWebSocket(username, token) {
    socket = new ReconnectingWebSocket("wss://gt5ldqfgv0.execute-api.eu-central-1.amazonaws.com/dev?token=" + token);

    socket.onopen = function(event) {
        data = {"action": "getRecentMessages"};
        socket.send(JSON.stringify(data));
    };

    socket.onmessage = function(message) {
        var data = JSON.parse(message.data);
        data["messages"].forEach(function(message) {
            if ($("#message-container").children(0).attr("id") == "empty-message") {
                $("#message-container").empty();
            }
            if (message["username"] === username) {
                $("#message-container").append("<div class='message self-message'><b>(You)</b> " + message["content"]);
            } else {
                $("#message-container").append("<div class='message'><b>(" + message["username"] + ")</b> " + message["content"]);
            }
            $("#message-container").children().last()[0].scrollIntoView();
        });
    };
}

// Sends a message to the websocket using the text in the post bar
function postMessage(token) {
    var content = $("#post-bar").val();
    if (content !== "") {
        data = {"action": "sendMessage",  "token": token, "content": content};
        socket.send(JSON.stringify(data));
        $("#post-bar").val("");
    }
}