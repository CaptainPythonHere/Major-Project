from django import forms
from MajorApp.models import UserModel

class URLform(forms.Form):
    url = forms.CharField(label='Your URL ',widget=forms.TextInput(attrs={'size': 50, }))
    #url = forms.TextInput(attrs={'size': 10})
class UserForm(forms.ModelForm):
    class Meta:
        model = UserModel
        fields = ['name', 'email', 'phone', 'text']
