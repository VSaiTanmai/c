from shap_explainer import FeatureAttributor
print("OK - FeatureAttributor class loaded")
print(f"  Methods: {[m for m in dir(FeatureAttributor) if not m.startswith('_')]}")
