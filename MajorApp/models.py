from django.db import models
from phonenumber_field.modelfields import PhoneNumberField
from phone_field import PhoneField

# Create your models here.
class UserModel(models.Model):
    name = models.CharField(max_length=100)
    phone = PhoneNumberField(primary_key=True, region='IN')
    email = models.EmailField()
    text = models.TextField(max_length=200)
