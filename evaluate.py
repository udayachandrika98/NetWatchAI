"""
NetWatchAI - Model Evaluation & Benchmarking
Evaluates the Isolation Forest model against other ML models on the NSL-KDD dataset.
Generates metrics, confusion matrices, ROC curves, and comparison tables.

Usage:
    python evaluate.py
    python evaluate.py --output results/

This script:
1. Downloads the NSL-KDD dataset (standard IDS benchmark)
2. Trains 4 models: Isolation Forest, Random Forest, SVM, Decision Tree
3. Evaluates each model with: Accuracy, Precision, Recall, F1-Score
4. Generates: Confusion Matrix, ROC Curve, Model Comparison Chart
5. Saves all results to the output directory
"""

import argparse
import os
import time
import warnings

import matplotlib
import numpy as np
import pandas as pd

matplotlib.use('Agg')  # Non-interactive backend

import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    auc,
    average_precision_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_curve,
)
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.svm import SVC
from sklearn.tree import DecisionTreeClassifier

warnings.filterwarnings('ignore')

# ──────────────────────────────────────────────
# NSL-KDD Dataset
# ──────────────────────────────────────────────

NSL_KDD_COLUMNS = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
    'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
    'num_compromised', 'root_shell', 'su_attempted', 'num_root',
    'num_file_creations', 'num_shells', 'num_access_files', 'num_outbound_cmds',
    'is_host_login', 'is_guest_login', 'count', 'srv_count', 'serror_rate',
    'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate',
    'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
    'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
    'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate',
    'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'label', 'difficulty'
]

# Attack categories in NSL-KDD
ATTACK_CATEGORIES = {
    'normal': 'Normal',
    # DoS attacks
    'back': 'DoS', 'land': 'DoS', 'neptune': 'DoS', 'pod': 'DoS',
    'smurf': 'DoS', 'teardrop': 'DoS', 'apache2': 'DoS', 'udpstorm': 'DoS',
    'processtable': 'DoS', 'mailbomb': 'DoS',
    # Probe attacks
    'satan': 'Probe', 'ipsweep': 'Probe', 'nmap': 'Probe', 'portsweep': 'Probe',
    'mscan': 'Probe', 'saint': 'Probe',
    # R2L attacks
    'guess_passwd': 'R2L', 'ftp_write': 'R2L', 'imap': 'R2L', 'phf': 'R2L',
    'multihop': 'R2L', 'warezmaster': 'R2L', 'warezclient': 'R2L', 'spy': 'R2L',
    'xlock': 'R2L', 'xsnoop': 'R2L', 'snmpguess': 'R2L', 'snmpgetattack': 'R2L',
    'httptunnel': 'R2L', 'sendmail': 'R2L', 'named': 'R2L', 'worm': 'R2L',
    # U2R attacks
    'buffer_overflow': 'U2R', 'loadmodule': 'U2R', 'rootkit': 'U2R', 'perl': 'U2R',
    'sqlattack': 'U2R', 'xterm': 'U2R', 'ps': 'U2R',
}


def download_nsl_kdd(data_dir):
    """Download NSL-KDD dataset if not present."""
    train_file = os.path.join(data_dir, "KDDTrain+.txt")
    test_file = os.path.join(data_dir, "KDDTest+.txt")

    if os.path.exists(train_file) and os.path.exists(test_file):
        print("[OK] NSL-KDD dataset found locally.")
        return train_file, test_file

    print("[*] Downloading NSL-KDD dataset...")
    import urllib.request

    base_url = "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/"
    urls = {
        "KDDTrain+.txt": base_url + "KDDTrain%2B.txt",
        "KDDTest+.txt": base_url + "KDDTest%2B.txt",
    }

    os.makedirs(data_dir, exist_ok=True)
    for filename, url in urls.items():
        filepath = os.path.join(data_dir, filename)
        print(f"    Downloading {filename}...")
        urllib.request.urlretrieve(url, filepath)

    print("[OK] Dataset downloaded successfully.")
    return train_file, test_file


def load_nsl_kdd(filepath):
    """Load and preprocess NSL-KDD dataset."""
    df = pd.read_csv(filepath, header=None, names=NSL_KDD_COLUMNS)

    # Clean label column
    df['label'] = df['label'].str.strip().str.rstrip('.')

    # Map to binary: Normal (0) vs Attack (1)
    df['binary_label'] = df['label'].apply(lambda x: 0 if x == 'normal' else 1)

    # Map to attack categories
    df['attack_category'] = df['label'].apply(
        lambda x: ATTACK_CATEGORIES.get(x, 'Unknown')
    )

    # Drop difficulty column
    df = df.drop('difficulty', axis=1)

    return df


def prepare_features(train_df, test_df):
    """Encode categorical features and scale numeric ones."""
    # Categorical columns to encode
    cat_cols = ['protocol_type', 'service', 'flag']

    # Combine for consistent encoding
    combined = pd.concat([train_df, test_df], axis=0)

    encoders = {}
    for col in cat_cols:
        le = LabelEncoder()
        combined[col] = le.fit_transform(combined[col].astype(str))
        encoders[col] = le

    # Split back
    train_encoded = combined.iloc[:len(train_df)].copy()
    test_encoded = combined.iloc[len(train_df):].copy()

    # Feature columns (exclude labels)
    feature_cols = [c for c in train_encoded.columns
                    if c not in ['label', 'binary_label', 'attack_category']]

    # Scale features
    scaler = StandardScaler()
    X_train = scaler.fit_transform(train_encoded[feature_cols])
    X_test = scaler.transform(test_encoded[feature_cols])

    y_train = train_encoded['binary_label'].values
    y_test = test_encoded['binary_label'].values

    return X_train, X_test, y_train, y_test, feature_cols


def evaluate_model(name, y_true, y_pred, y_scores=None):
    """Calculate all evaluation metrics for a model."""
    metrics = {
        'Model': name,
        'Accuracy': accuracy_score(y_true, y_pred),
        'Precision': precision_score(y_true, y_pred, zero_division=0),
        'Recall': recall_score(y_true, y_pred, zero_division=0),
        'F1-Score': f1_score(y_true, y_pred, zero_division=0),
    }

    cm = confusion_matrix(y_true, y_pred)
    report = classification_report(y_true, y_pred, target_names=['Normal', 'Attack'], output_dict=True)

    return metrics, cm, report


def plot_confusion_matrix(cm, model_name, output_dir):
    """Generate and save confusion matrix heatmap."""
    plt.figure(figsize=(8, 6))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
                xticklabels=['Normal', 'Attack'],
                yticklabels=['Normal', 'Attack'],
                annot_kws={'size': 16})
    plt.title(f'Confusion Matrix — {model_name}', fontsize=14, fontweight='bold')
    plt.ylabel('Actual', fontsize=12)
    plt.xlabel('Predicted', fontsize=12)
    plt.tight_layout()
    filepath = os.path.join(output_dir, f'confusion_matrix_{model_name.lower().replace(" ", "_")}.png')
    plt.savefig(filepath, dpi=150, bbox_inches='tight')
    plt.close()
    return filepath


def plot_all_confusion_matrices(results, output_dir):
    """Plot all confusion matrices in a single figure."""
    fig, axes = plt.subplots(2, 2, figsize=(14, 12))
    fig.suptitle('Confusion Matrices — Model Comparison', fontsize=16, fontweight='bold')

    for idx, (name, data) in enumerate(results.items()):
        ax = axes[idx // 2][idx % 2]
        sns.heatmap(data['cm'], annot=True, fmt='d', cmap='Blues',
                    xticklabels=['Normal', 'Attack'],
                    yticklabels=['Normal', 'Attack'],
                    annot_kws={'size': 14}, ax=ax)
        ax.set_title(name, fontsize=13, fontweight='bold')
        ax.set_ylabel('Actual')
        ax.set_xlabel('Predicted')

    plt.tight_layout()
    filepath = os.path.join(output_dir, 'confusion_matrices_all.png')
    plt.savefig(filepath, dpi=150, bbox_inches='tight')
    plt.close()
    return filepath


def plot_roc_curves(results, output_dir):
    """Plot ROC curves for all models."""
    plt.figure(figsize=(10, 8))

    colors = ['#00e5ff', '#7c4dff', '#f87171', '#34d399']

    for idx, (name, data) in enumerate(results.items()):
        if data.get('y_scores') is not None:
            fpr, tpr, _ = roc_curve(data['y_true'], data['y_scores'])
            roc_auc = auc(fpr, tpr)
            plt.plot(fpr, tpr, color=colors[idx % len(colors)],
                     lw=2, label=f'{name} (AUC = {roc_auc:.4f})')

    plt.plot([0, 1], [0, 1], 'k--', lw=1, alpha=0.5, label='Random (AUC = 0.5)')
    plt.xlim([0.0, 1.0])
    plt.ylim([0.0, 1.05])
    plt.xlabel('False Positive Rate', fontsize=12)
    plt.ylabel('True Positive Rate', fontsize=12)
    plt.title('ROC Curve — Model Comparison', fontsize=14, fontweight='bold')
    plt.legend(loc='lower right', fontsize=11)
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    filepath = os.path.join(output_dir, 'roc_curves.png')
    plt.savefig(filepath, dpi=150, bbox_inches='tight')
    plt.close()
    return filepath


def plot_precision_recall_curves(results, output_dir):
    """Plot Precision-Recall curves for all models."""
    plt.figure(figsize=(10, 8))

    colors = ['#00e5ff', '#7c4dff', '#f87171', '#34d399']

    for idx, (name, data) in enumerate(results.items()):
        if data.get('y_scores') is not None:
            precision, recall, _ = precision_recall_curve(data['y_true'], data['y_scores'])
            ap = average_precision_score(data['y_true'], data['y_scores'])
            plt.plot(recall, precision, color=colors[idx % len(colors)],
                     lw=2, label=f'{name} (AP = {ap:.4f})')

    plt.xlabel('Recall', fontsize=12)
    plt.ylabel('Precision', fontsize=12)
    plt.title('Precision-Recall Curve — Model Comparison', fontsize=14, fontweight='bold')
    plt.legend(loc='lower left', fontsize=11)
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    filepath = os.path.join(output_dir, 'precision_recall_curves.png')
    plt.savefig(filepath, dpi=150, bbox_inches='tight')
    plt.close()
    return filepath


def plot_model_comparison(metrics_list, output_dir):
    """Bar chart comparing all models across metrics."""
    df = pd.DataFrame(metrics_list)
    df_melted = df.melt(id_vars='Model', var_name='Metric', value_name='Score')

    plt.figure(figsize=(12, 6))
    ax = sns.barplot(data=df_melted, x='Metric', y='Score', hue='Model',
                     palette=['#00e5ff', '#7c4dff', '#f87171', '#34d399'])
    plt.title('Model Performance Comparison', fontsize=14, fontweight='bold')
    plt.ylabel('Score', fontsize=12)
    plt.xlabel('', fontsize=12)
    plt.ylim(0, 1.05)
    plt.legend(title='Model', fontsize=10)

    # Add value labels on bars
    for container in ax.containers:
        ax.bar_label(container, fmt='%.3f', fontsize=8, padding=3)

    plt.tight_layout()
    filepath = os.path.join(output_dir, 'model_comparison.png')
    plt.savefig(filepath, dpi=150, bbox_inches='tight')
    plt.close()
    return filepath


def plot_attack_distribution(train_df, test_df, output_dir):
    """Plot attack category distribution in the dataset."""
    fig, axes = plt.subplots(1, 2, figsize=(14, 5))

    for ax, (name, data) in zip(axes, [('Training Set', train_df), ('Test Set', test_df)], strict=True):
        counts = data['attack_category'].value_counts()
        colors = ['#34d399', '#f87171', '#fbbf24', '#00e5ff', '#7c4dff']
        ax.pie(counts.values, labels=counts.index, autopct='%1.1f%%',
               colors=colors[:len(counts)], startangle=90)
        ax.set_title(f'{name} — Attack Distribution', fontsize=12, fontweight='bold')

    plt.tight_layout()
    filepath = os.path.join(output_dir, 'attack_distribution.png')
    plt.savefig(filepath, dpi=150, bbox_inches='tight')
    plt.close()
    return filepath


def plot_training_time(time_dict, output_dir):
    """Bar chart of training times."""
    plt.figure(figsize=(8, 5))
    models = list(time_dict.keys())
    times = list(time_dict.values())
    colors = ['#00e5ff', '#7c4dff', '#f87171', '#34d399']

    bars = plt.bar(models, times, color=colors[:len(models)], edgecolor='white', linewidth=0.5)
    plt.title('Model Training Time Comparison', fontsize=14, fontweight='bold')
    plt.ylabel('Time (seconds)', fontsize=12)
    plt.grid(axis='y', alpha=0.3)

    for bar, t in zip(bars, times, strict=True):
        plt.text(bar.get_x() + bar.get_width()/2., bar.get_height() + 0.1,
                f'{t:.2f}s', ha='center', fontsize=11, fontweight='bold')

    plt.tight_layout()
    filepath = os.path.join(output_dir, 'training_time.png')
    plt.savefig(filepath, dpi=150, bbox_inches='tight')
    plt.close()
    return filepath


def main():
    parser = argparse.ArgumentParser(description="NetWatchAI Model Evaluation")
    parser.add_argument("--output", type=str, default="results", help="Output directory for results")
    args = parser.parse_args()

    output_dir = args.output
    data_dir = os.path.join("data", "nsl_kdd")
    os.makedirs(output_dir, exist_ok=True)

    print("=" * 60)
    print("  NetWatchAI — Model Evaluation & Benchmarking")
    print("=" * 60)
    print()

    # Step 1: Download and load dataset
    print("[1/6] Loading NSL-KDD dataset...")
    train_file, test_file = download_nsl_kdd(data_dir)
    train_df = load_nsl_kdd(train_file)
    test_df = load_nsl_kdd(test_file)
    print(f"      Training samples: {len(train_df):,}")
    print(f"      Test samples:     {len(test_df):,}")
    print(f"      Training attacks: {(train_df['binary_label'] == 1).sum():,} ({(train_df['binary_label'] == 1).mean()*100:.1f}%)")
    print(f"      Test attacks:     {(test_df['binary_label'] == 1).sum():,} ({(test_df['binary_label'] == 1).mean()*100:.1f}%)")
    print()

    # Plot dataset distribution
    print("[2/6] Plotting dataset distribution...")
    plot_attack_distribution(train_df, test_df, output_dir)
    print("      Saved: attack_distribution.png")
    print()

    # Step 2: Prepare features
    print("[3/6] Preparing features...")
    X_train, X_test, y_train, y_test, feature_cols = prepare_features(train_df, test_df)
    print(f"      Features: {len(feature_cols)}")
    print(f"      X_train shape: {X_train.shape}")
    print(f"      X_test shape:  {X_test.shape}")
    print()

    # Step 3: Train and evaluate models
    print("[4/6] Training and evaluating models...")
    print()

    results = {}
    metrics_list = []
    training_times = {}

    # ── Model 1: Isolation Forest (Our model) ──
    print("  [*] Isolation Forest (NetWatchAI)...")
    start = time.time()
    iso_forest = IsolationForest(n_estimators=100, contamination=0.1, random_state=42, n_jobs=-1)
    iso_forest.fit(X_train)
    training_times['Isolation Forest'] = time.time() - start

    iso_pred = iso_forest.predict(X_test)
    # Convert: -1 (anomaly) → 1 (attack), 1 (normal) → 0 (normal)
    iso_pred_binary = np.where(iso_pred == -1, 1, 0)
    iso_scores = -iso_forest.score_samples(X_test)  # Higher = more anomalous

    metrics, cm, report = evaluate_model("Isolation Forest", y_test, iso_pred_binary, iso_scores)
    results['Isolation Forest'] = {'cm': cm, 'report': report, 'y_true': y_test, 'y_scores': iso_scores, 'y_pred': iso_pred_binary}
    metrics_list.append(metrics)
    print(f"      Accuracy: {metrics['Accuracy']:.4f}  F1: {metrics['F1-Score']:.4f}  Time: {training_times['Isolation Forest']:.2f}s")

    # ── Model 2: Random Forest ──
    print("  [*] Random Forest...")
    start = time.time()
    rf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    rf.fit(X_train, y_train)
    training_times['Random Forest'] = time.time() - start

    rf_pred = rf.predict(X_test)
    rf_scores = rf.predict_proba(X_test)[:, 1]

    metrics, cm, report = evaluate_model("Random Forest", y_test, rf_pred, rf_scores)
    results['Random Forest'] = {'cm': cm, 'report': report, 'y_true': y_test, 'y_scores': rf_scores, 'y_pred': rf_pred}
    metrics_list.append(metrics)
    print(f"      Accuracy: {metrics['Accuracy']:.4f}  F1: {metrics['F1-Score']:.4f}  Time: {training_times['Random Forest']:.2f}s")

    # ── Model 3: Decision Tree ──
    print("  [*] Decision Tree...")
    start = time.time()
    dt = DecisionTreeClassifier(random_state=42, max_depth=20)
    dt.fit(X_train, y_train)
    training_times['Decision Tree'] = time.time() - start

    dt_pred = dt.predict(X_test)
    dt_scores = dt.predict_proba(X_test)[:, 1]

    metrics, cm, report = evaluate_model("Decision Tree", y_test, dt_pred, dt_scores)
    results['Decision Tree'] = {'cm': cm, 'report': report, 'y_true': y_test, 'y_scores': dt_scores, 'y_pred': dt_pred}
    metrics_list.append(metrics)
    print(f"      Accuracy: {metrics['Accuracy']:.4f}  F1: {metrics['F1-Score']:.4f}  Time: {training_times['Decision Tree']:.2f}s")

    # ── Model 4: SVM ──
    print("  [*] SVM (using subset for speed)...")
    # SVM is slow on large datasets — use a subset
    svm_size = min(20000, len(X_train))
    indices = np.random.RandomState(42).choice(len(X_train), svm_size, replace=False)
    X_train_svm = X_train[indices]
    y_train_svm = y_train[indices]

    start = time.time()
    svm = SVC(kernel='rbf', probability=True, random_state=42, C=1.0)
    svm.fit(X_train_svm, y_train_svm)
    training_times['SVM'] = time.time() - start

    svm_pred = svm.predict(X_test)
    svm_scores = svm.predict_proba(X_test)[:, 1]

    metrics, cm, report = evaluate_model("SVM", y_test, svm_pred, svm_scores)
    results['SVM'] = {'cm': cm, 'report': report, 'y_true': y_test, 'y_scores': svm_scores, 'y_pred': svm_pred}
    metrics_list.append(metrics)
    print(f"      Accuracy: {metrics['Accuracy']:.4f}  F1: {metrics['F1-Score']:.4f}  Time: {training_times['SVM']:.2f}s")
    print()

    # Step 4: Generate plots
    print("[5/6] Generating evaluation plots...")

    plot_all_confusion_matrices(results, output_dir)
    print("      Saved: confusion_matrices_all.png")

    for name, data in results.items():
        plot_confusion_matrix(data['cm'], name, output_dir)
        print(f"      Saved: confusion_matrix_{name.lower().replace(' ', '_')}.png")

    plot_roc_curves(results, output_dir)
    print("      Saved: roc_curves.png")

    plot_precision_recall_curves(results, output_dir)
    print("      Saved: precision_recall_curves.png")

    plot_model_comparison(metrics_list, output_dir)
    print("      Saved: model_comparison.png")

    plot_training_time(training_times, output_dir)
    print("      Saved: training_time.png")
    print()

    # Step 5: Save results
    print("[6/6] Saving results...")

    # Save metrics table
    metrics_df = pd.DataFrame(metrics_list)
    metrics_df.to_csv(os.path.join(output_dir, 'model_metrics.csv'), index=False)
    print("      Saved: model_metrics.csv")

    # Save detailed report
    report_path = os.path.join(output_dir, 'evaluation_report.txt')
    with open(report_path, 'w') as f:
        f.write("=" * 60 + "\n")
        f.write("  NetWatchAI — Model Evaluation Report\n")
        f.write("=" * 60 + "\n\n")
        f.write("Dataset: NSL-KDD\n")
        f.write(f"Training samples: {len(train_df):,}\n")
        f.write(f"Test samples: {len(test_df):,}\n\n")

        f.write("-" * 60 + "\n")
        f.write("MODEL COMPARISON\n")
        f.write("-" * 60 + "\n\n")
        f.write(metrics_df.to_string(index=False))
        f.write("\n\n")

        f.write("-" * 60 + "\n")
        f.write("TRAINING TIMES\n")
        f.write("-" * 60 + "\n\n")
        for model, t in training_times.items():
            f.write(f"  {model}: {t:.2f} seconds\n")
        f.write("\n")

        for name, data in results.items():
            f.write("-" * 60 + "\n")
            f.write(f"DETAILED REPORT: {name}\n")
            f.write("-" * 60 + "\n\n")
            f.write(classification_report(data['y_true'], data['y_pred'],
                                          target_names=['Normal', 'Attack']))
            f.write("\nConfusion Matrix:\n")
            f.write(str(data['cm']))
            f.write("\n\n")

        # Key findings
        f.write("=" * 60 + "\n")
        f.write("KEY FINDINGS\n")
        f.write("=" * 60 + "\n\n")

        best_model = max(metrics_list, key=lambda x: x['F1-Score'])
        f.write(f"Best overall model (by F1-Score): {best_model['Model']}\n")
        f.write(f"  Accuracy:  {best_model['Accuracy']:.4f}\n")
        f.write(f"  Precision: {best_model['Precision']:.4f}\n")
        f.write(f"  Recall:    {best_model['Recall']:.4f}\n")
        f.write(f"  F1-Score:  {best_model['F1-Score']:.4f}\n\n")

        iso_metrics = metrics_list[0]  # Isolation Forest is always first
        f.write("Isolation Forest (NetWatchAI's model):\n")
        f.write(f"  Accuracy:  {iso_metrics['Accuracy']:.4f}\n")
        f.write(f"  Precision: {iso_metrics['Precision']:.4f}\n")
        f.write(f"  Recall:    {iso_metrics['Recall']:.4f}\n")
        f.write(f"  F1-Score:  {iso_metrics['F1-Score']:.4f}\n\n")

        f.write("Note: Isolation Forest is unsupervised (requires no labeled data),\n")
        f.write("while Random Forest, Decision Tree, and SVM are supervised (require labels).\n")
        f.write("This is a significant advantage in real-world scenarios where labeled\n")
        f.write("attack data is often unavailable.\n")

    print("      Saved: evaluation_report.txt")
    print()

    # Print summary
    print("=" * 60)
    print("  RESULTS SUMMARY")
    print("=" * 60)
    print()
    print(metrics_df.to_string(index=False))
    print()
    print(f"  Best model (F1): {best_model['Model']} ({best_model['F1-Score']:.4f})")
    print()
    print(f"  All results saved to: {output_dir}/")
    print()
    print("  Files generated:")
    print("    - model_metrics.csv")
    print("    - evaluation_report.txt")
    print("    - confusion_matrices_all.png")
    print("    - roc_curves.png")
    print("    - precision_recall_curves.png")
    print("    - model_comparison.png")
    print("    - attack_distribution.png")
    print("    - training_time.png")
    print()


if __name__ == "__main__":
    main()
