from django.urls import path
from . import views

urlpatterns = [
    path('lcg/', views.generate_lcg, name='lcg'),
]
