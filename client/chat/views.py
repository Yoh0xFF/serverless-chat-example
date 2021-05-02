from django.contrib.auth.decorators import login_required
from django.shortcuts import render
import jwt


@login_required
def index(request):
    token = jwt.encode(
        {"username": request.user.username}, "TOP_SECRET", algorithm="HS256"
    ).decode("utf-8")
    return render(request, "chat/index.html", {"token": token})
