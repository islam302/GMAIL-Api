from django.urls import path
from . import views

urlpatterns = [
    path('google_auth/', views.google_auth, name='google_auth'),
    path('google_auth/callback/', views.google_auth_callback, name='google_auth_callback'),
]
