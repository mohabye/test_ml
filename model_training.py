import pandas as pd
import numpy as np
import pickle
import time
from sklearn.ensemble import RandomForestClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

def load_training_data(train_path):
    train_data = pd.read_csv(train_path)
    X_train = train_data.drop('label', axis=1)
    y_train = train_data['label']
    return X_train, y_train

def load_test_data(test_path):
    test_data = pd.read_csv(test_path)
    X_test = test_data.drop('label', axis=1)
    y_test = test_data['label']
    return X_test, y_test

def train_random_forest(X_train, y_train):
    start_time = time.time()
    
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=20,
        min_samples_split=10,
        min_samples_leaf=4,
        random_state=42,
        n_jobs=-1
    )
    
    model.fit(X_train, y_train)
    
    training_time = time.time() - start_time
    print(f"Random Forest training completed in {training_time:.2f} seconds")
    
    return model

def train_neural_network(X_train, y_train):
    start_time = time.time()
    
    model = MLPClassifier(
        hidden_layer_sizes=(100, 50),
        activation='relu',
        solver='adam',
        alpha=0.0001,
        batch_size=256,
        learning_rate='adaptive',
        max_iter=200,
        random_state=42
    )
    
    model.fit(X_train, y_train)
    
    training_time = time.time() - start_time
    print(f"Neural Network training completed in {training_time:.2f} seconds")
    
    return model

def evaluate_model(model, X_test, y_test):
    y_pred = model.predict(X_test)
    
    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred)
    recall = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    conf_matrix = confusion_matrix(y_test, y_pred)
    
    print(f"Model Evaluation Metrics:")
    print(f"Accuracy: {accuracy:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall: {recall:.4f}")
    print(f"F1 Score: {f1:.4f}")
    print(f"Confusion Matrix:")
    print(conf_matrix)
    
    return {
        'accuracy': accuracy,
        'precision': precision,
        'recall': recall,
        'f1': f1,
        'confusion_matrix': conf_matrix
    }

def save_model(model, model_path):
    with open(model_path, 'wb') as f:
        pickle.dump(model, f)
    print(f"Model saved to {model_path}")

def main():
    train_path = 'D:\waf_ml\processed/train_data.csv'
    test_path = 'D:\waf_ml\attack_traffic.csv'
    model_path = 'D:\waf_m\model\waf_model.pkl'
    
    X_train, y_train = load_training_data(train_path)
    X_test, y_test = load_test_data(test_path)
    
    print("Training Random Forest model...")
    rf_model = train_random_forest(X_train, y_train)
    rf_metrics = evaluate_model(rf_model, X_test, y_test)
    
    print("\nTraining Neural Network model...")
    nn_model = train_neural_network(X_train, y_train)
    nn_metrics = evaluate_model(nn_model, X_test, y_test)
    
    if rf_metrics['f1'] >= nn_metrics['f1']:
        print("Random Forest model performed better. Saving this model.")
        save_model(rf_model, model_path)
    else:
        print("Neural Network model performed better. Saving this model.")
        save_model(nn_model, model_path)

if __name__ == "__main__":
    main()
