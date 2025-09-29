from django.shortcuts import render

def index(request):
    return render(request, 'information_protection/index.html')

