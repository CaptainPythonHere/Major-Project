from django import forms
from MajorApp.models import UserModel

class URLform(forms.Form):
    url = forms.CharField(widget=forms.TextInput)

class UserForm(forms.ModelForm):
    class Meta:
        model = UserModel
        fields = '__all__'
