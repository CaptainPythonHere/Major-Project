from django.shortcuts import render
from MajorApp.forms import URLform, UserForm
from MajorApp import predict
# Create your views here.

def index(request):
    getForm = UserForm()
    URL = URLform()
    if request.method == "POST" and 'urlform' in request.POST:
        URL = URLform(request.POST)
        if URL.is_valid():
            cleanedurl = URL.cleaned_data['url']
            #print(cleanedurl)
            #print(str(cleanedurl))
            string_url = str(cleanedurl)
            predicted = predict.predictURL(string_url)
            #print(predicted)
            return render(request,'majorapp/index.html',{'URL':URL,'predicted':predicted, 'getForm':getForm})
    #else:
    #    url = URLform()

    if request.method == "POST" and 'userform' in request.POST:
        getForm = UserForm(request.POST)
        if getForm.is_valid():
            getForm.save(commit=True)
            string = "Your feedback has been submitted!"
            return render(request,'majorapp/index.html',{'URL':URL, 'getForm':getForm,'string':string})

    #else:
    #    getForm = UserForm()
    return render(request, 'majorapp/index.html',{'URL':URL, 'getForm':getForm})
