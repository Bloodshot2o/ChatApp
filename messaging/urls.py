from django.urls import path
from . import views

urlpatterns = [
    path('register/', views.register, name='register'),
    path('login/', views.login_view, name='login'),
    path('send_message/', views.send_message, name='send_message'),
    path('message_history/', views.message_history, name='message_history'),
    path('',views.home, name='home'),
]
