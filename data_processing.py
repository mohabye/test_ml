import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

def load_data(normal_file, attack_file):
    normal_data = pd.read_csv(normal_file)
    normal_data['label'] = 0
    
    attack_data = pd.read_csv(attack_file)
    attack_data['label'] = 1
    
    combined_data = pd.concat([normal_data, attack_data], ignore_index=True)
    return combined_data

def preprocess_data(data):
    data = data.dropna()
    
    categorical_cols = data.select_dtypes(include=['object']).columns
    for col in categorical_cols:
        data[col] = data[col].astype('category').cat.codes
    
    return data

def split_dataset(data, test_size=0.2, random_state=42):
    X = data.drop('label', axis=1)
    y = data['label']
    
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=random_state, stratify=y
    )
    
    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_test = scaler.transform(X_test)
    
    return X_train, X_test, y_train, y_test, scaler

def save_processed_data(X_train, X_test, y_train, y_test, train_path, test_path):
    train_data = pd.DataFrame(X_train)
    train_data['label'] = y_train.values
    train_data.to_csv(train_path, index=False)
    
    test_data = pd.DataFrame(X_test)
    test_data['label'] = y_test.values
    test_data.to_csv(test_path, index=False)

def main():
    normal_file = 'D:\waf_ml\n_traffic.csv'
    attack_file = 'D:\waf_mlattack_traffic.csv'
    
    data = load_data(normal_file, attack_file)
    processed_data = preprocess_data(data)
    
    X_train, X_test, y_train, y_test, scaler = split_dataset(processed_data)
    
    save_processed_data(
        X_train, X_test, y_train, y_test,
        'D:\waf_ml\processed/train_data.csv',
        'D:\waf_mlprocessed/test_data.csv'
    )
    
    print("Data preprocessing completed successfully.")

if __name__ == "__main__":
    main()
