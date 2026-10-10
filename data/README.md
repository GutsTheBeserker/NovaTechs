# Dataset Provenance, Specification & Methodology

## 1. Selected Labelled Dataset

The machine-learning pipeline is trained and evaluated on the **Mendeley / IEEE Data in Brief Phishing Websites Benchmark Dataset** (Vrbančič et al., 2020).

### Dataset Metadata
- **Source Repository**: [GregaVrbancic/Phishing-Dataset](https://github.com/GregaVrbancic/Phishing-Dataset)
- **Primary Publication**: Vrbančič, G., Fister Jr, I., & Podgorelec, V. (2020). *A full dataset of phishing websites*. Data in Brief, 32, 106111. DOI: `10.1016/j.dib.2020.106111`
- **License**: Creative Commons Attribution 4.0 International (**CC BY 4.0**)
- **Data Acquisition URL**: `https://raw.githubusercontent.com/GregaVrbancic/Phishing-Dataset/master/dataset_small.csv`
- **File Format**: Comma-Separated Values (CSV), UTF-8

---

## 2. Actual Class Distribution

The dataset contains **58,645** labelled samples:

| Class | Label Value | Sample Count | Percentage | Description |
| :--- | :--- | :--- | :--- | :--- |
| **Legitimate Websites** | `0` | **27,998** | **47.74%** | Sampled from Alexa / Cisco Umbrella authoritative top rankings |
| **Phishing Websites** | `1` | **30,647** | **52.26%** | Verified active credential-theft kits sourced from PhishTank and OpenPhish |
| **Total** | — | **58,645** | **100.0%** | Balanced binary classification benchmark |

---

## 3. Extracted URL & Domain Feature Subset

To guarantee **privacy preservation** and **prevent server-side browsing**, the ML model is trained exclusively on the **40 URL and domain topological attributes** that do not require external HTTP requests, resolving DNS, or accessing webpage bodies:

1. `length_url`: Total character length of URL
2. `domain_length`: Total character length of registered domain and host
3. `qty_dot_url`: Count of dot (`.`) characters in URL
4. `qty_hyphen_url`: Count of hyphen (`-`) characters in URL
5. `qty_underline_url`: Count of underscore (`_`) characters in URL
6. `qty_slash_url`: Count of forward slash (`/`) characters in URL
7. `qty_questionmark_url`: Count of question marks (`?`) in URL
8. `qty_equal_url`: Count of equal signs (`=`) in URL
9. `qty_at_url`: Count of `@` symbols in URL
10. `qty_and_url`: Count of ampersands (`&`) in URL
11. `qty_exclamation_url`: Count of exclamation points (`!`) in URL
12. `qty_space_url`: Count of spaces in URL
13. `qty_tilde_url`: Count of tildes (`~`) in URL
14. `qty_comma_url`: Count of commas (`,`) in URL
15. `qty_plus_url`: Count of plus signs (`+`) in URL
16. `qty_asterisk_url`: Count of asterisks (`*`) in URL
17. `qty_hashtag_url`: Count of hash symbols (`#`) in URL
18. `qty_dollar_url`: Count of dollar signs (`$`) in URL
19. `qty_percent_url`: Count of percent symbols (`%`) in URL
20. `qty_tld_url`: Count of Top-Level Domains present in URL
21. `qty_dot_domain`: Count of dots in domain
22. `qty_hyphen_domain`: Count of hyphens in domain
23. `qty_underline_domain`: Count of underscores in domain
24. `qty_slash_domain`: Count of slashes in domain
25. `qty_questionmark_domain`: Count of question marks in domain
26. `qty_equal_domain`: Count of equal signs in domain
27. `qty_at_domain`: Count of `@` in domain
28. `qty_and_domain`: Count of ampersands in domain
29. `qty_exclamation_domain`: Count of exclamation points in domain
30. `qty_space_domain`: Count of spaces in domain
31. `qty_tilde_domain`: Count of tildes in domain
32. `qty_comma_domain`: Count of commas in domain
33. `qty_plus_domain`: Count of plus signs in domain
34. `qty_asterisk_domain`: Count of asterisks in domain
35. `qty_hashtag_domain`: Count of hash symbols in domain
36. `qty_dollar_domain`: Count of dollar signs in domain
37. `qty_percent_domain`: Count of percent signs in domain
38. `qty_vowels_domain`: Count of vowel characters in domain
39. `domain_in_ip`: Boolean flag indicating if host is an IPv4/IPv6 address
40. `server_client_domain`: Boolean flag indicating occurrence of "server" or "client" keyword in domain

---

## 4. Automated Download & Reproducibility Instructions

The raw dataset can be downloaded using the automated script:
```bash
python backend/scripts/download_data.py
```
Or directly via curl / PowerShell:
```bash
curl -o data/raw/dataset_small.csv https://raw.githubusercontent.com/GregaVrbancic/Phishing-Dataset/master/dataset_small.csv
```

---

## 5. Model Limitations & Ethical Privacy Constraints

1. **No Page-Content Analysis in ML Model**: The ML model inspects **URL topological features only**. It does **not** evaluate DOM structure, rendered HTML, or images (DOM structure is evaluated client-side by the deterministic rule engine).
2. **Temporal Drift**: Phishing kits frequently modify domain naming strategies over time (fast-flux, brand tunneling). The model should be retrained periodically against active PhishTank feeds.
3. **No Autonomous Server-Side Web Fetching**: The backend **never** fetches, crawls, or opens submitted URLs.
