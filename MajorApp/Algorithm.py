#!/usr/bin/env python
# coding: utf-8

# In[1]:


import pandas as pd
import numpy as np
#import seaborn as sns
#import matplotlib.pyplot as plt
#get_ipython().run_line_magic('matplotlib', 'inline')
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier

df = pd.read_csv('MajorApp/dataset.csv')
X = df[['SSLfinal_State', 'URL_of_Anchor', 'Prefix_Suffix', 'web_traffic', 'having_Sub_Domain',
        'Request_URL','Links_in_tags','SFH']]
y = df['Result']
X_test, X_train, y_test, y_train = train_test_split(X, y, test_size = 0.3, random_state = 42)
rfc = RandomForestClassifier(n_estimators=15)
rfc.fit(X_train, y_train)


# In[ ]:
