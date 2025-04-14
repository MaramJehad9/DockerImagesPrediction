<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  
</head>
<body>

  <h1>🐳 Docker Images Vulnerability Prediction</h1>

  <p>
    This repository contains everything used to collect, process, and analyze Docker images for predicting whether they are secure or insecure using machine learning.
  </p>

  <hr>

  <h2>📂 <strong>Files Overview</strong></h2>
  <ul>
    <li>
      <strong>Docker_Images_Features.xlsx</strong><br>
      Contains the final dataset with <strong>778 Docker images</strong> and <strong>15 features</strong> extracted from each image. These features include vulnerability counts, severity levels, base image info, package manager, number of pulls, and more.
    </li>
    <br>
    <li>
      <strong>Python Scripts (.py files)</strong><br>
      These scripts were used to <strong>collect and extract features</strong> from Docker images:
      <ul>
        <li><code>base_imgs_pull.py</code> – Pulls base images from Docker Hub</li>
        <li><code>docker_img_ls.py</code> – Retrieves metadata (tag, size, update time)</li>
        <li><code>docker_scan.py</code> – Scans images using the Snyk CLI</li>
        <li><code>extract_search_images.py</code> – Searches for image names using keywords</li>
        <li><code>image_features_extracting.py</code> – Extracts features from scan reports</li>
        <li><code>inspect_imgs.py</code> – Retrieves additional image metadata</li>
      </ul>
    </li>
    <br>
    <li>
      <strong>random_forest_model.pkl</strong><br>
      A trained <strong>Random Forest Classifier</strong> used to predict whether a Docker image is secure or insecure, based on the features in the dataset.
    </li>
  </ul>

  <hr>

  <h2>📌 <strong>Project Summary</strong></h2>
  <p>
    The purpose of this project is to use real Docker image data to build a machine learning model that can predict image security status. The workflow includes:
  </p>
  <ol>
    <li><strong>Collecting Docker images</strong> (official, popular, and community-contributed)</li>
    <li><strong>Scanning for vulnerabilities</strong> using <strong>Snyk CLI</strong></li>
    <li><strong>Extracting relevant features</strong> (severity, base image, dependencies, etc.)</li>
    <li><strong>Labeling each image</strong> as <em>Secure</em> or <em>Insecure</em></li>
    <li><strong>Training a machine learning model</strong> to classify new images</li>
  </ol>

  <p>
    Feel free to explore the code, dataset, and model. Let me know if you have any questions or suggestions!
  </p>

</body>
</html>
