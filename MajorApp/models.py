from django.db import models
from phonenumber_field.modelfields import PhoneNumberField
from phone_field import PhoneField

# Create your models here.
class UserModel(models.Model):

    name = models.CharField(max_length=100)
    phone = models.CharField(max_length=10)
    email = models.EmailField()
    text = models.TextField(primary_key=True,max_length=500)
    datetime = models.DateTimeField(auto_now_add=True)

    
