import subprocess
import sys

# Exécute cli.py sur un fichier d'exemple minimaliste.
# Remplace "example.dockerfile" par un fichier Dockerfile de test approprié
# dans ton répertoire 'examples'.
try:
    result = subprocess.run([
        "python", "/app/jasapp/cli.py",
        "/app/examples/example.healthcheck.Dockerfile",
        "--type", "dockerfile"
    ], capture_output=True, text=True, check=True)

    # Affiche la sortie standard et d'erreur de la commande (pour le débogage)
    print("stdout:", result.stdout)
    print("stderr:", result.stderr)

    # Tu peux ajouter des vérifications supplémentaires ici, par exemple :
    # if "Specific error message" in result.stderr:
    #     sys.exit(1)

    sys.exit(0)  # Succès

except subprocess.CalledProcessError as e:
    print(f"Health check failed: {e}", file=sys.stderr)
    print("stdout:", e.stdout)
    print("stderr:", e.stderr)
    sys.exit(1)  # Échec
