<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  
</head>
<body>

  <h1> Docker Images Vulnerability Prediction</h1>

  <p>
    This repository contains everything used to collect, process, and analyze Docker images for predicting whether they are secure or insecure using machine learning.
  </p>

  <hr>

  <h2> <strong>Files Overview</strong></h2>
  <ul>
    <li>
      <strong>Docker_Images_Features.xlsx</strong><br>
      Contains the final dataset with <strong>778 Docker images</strong> and <strong>15 features</strong> extracted from each image. These features include vulnerability counts, severity levels, base image info, package manager, number of pulls, and more.
    </li>
    <br>
    <li>
      <strong>Python Scripts (.py files in Code folder)</strong><br>
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

  <h2> <strong>Project Summary</strong></h2>

<p>
  This project focuses on building a machine learning model that can predict whether a Docker image is secure or potentially malicious, based on real-world data collected from Docker Hub. The process involves the following key steps:
</p>

<ol>
  <li><strong>Collecting Docker images</strong> — including official, popular, and community-contributed images across different categories.</li>
  <li><strong>Scanning for vulnerabilities</strong> using the <strong>Snyk CLI</strong>, which checks for known security issues in each image.</li>
  <li><strong>Extracting key features</strong> — such as severity levels, base image, number of dependencies, and more.</li>
  <li><strong>Labeling each image</strong> as either <em>Secure</em> or <em>Insecure</em> based on scan results and recommendations.</li>
  <li><strong>Training and testing a machine learning model</strong> to automatically classify new Docker images.</li>
</ol>

<p>
  This work is inspired by the study conducted by <strong>Aldiabat et al. (2024)</strong>, who developed an efficient Random Forest-based classifier to detect malicious Docker images using a custom dataset of 14 security-related features. Their model achieved impressive results — including a <strong>99% F1-score</strong> and <strong>100% AUC</strong> — demonstrating the potential of machine learning in enhancing Docker image security.  
  <a href="https://ieeexplore.ieee.org/document/10768874" target="_blank">📄 Read the full paper on IEEE Xplore</a>
</p>


</body>
</html>
