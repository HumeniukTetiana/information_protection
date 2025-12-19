from django.urls import path
from . import views

app_name = 'lcg'  # добавляем namespace

urlpatterns = [
    path('', views.generate_lcg, name='lcg'),  # имя для reverse внутри namespace
]
