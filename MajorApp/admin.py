from django.contrib import admin
from MajorApp.models import UserModel
# Register your models here.

class UserAdmin(admin.ModelAdmin):
    list_display = ('name', 'text', 'datetime')
    search_fields = ['name', 'text','email']

admin.site.register(UserModel,UserAdmin)
