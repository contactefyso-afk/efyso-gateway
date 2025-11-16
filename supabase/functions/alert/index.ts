// Fichier: supabase/functions/alert/index.ts

// Importer le serveur Deno pour gérer les requêtes HTTP
import { serve } from 'https://deno.land/std@0.177.0/http/server.ts';

// Récupère les secrets sécurisés du Supabase Vault
// Ces variables sont lues à partir des secrets que vous avez enregistrés :
// MONCASH_CLIENT_ID (Business Key) et MONCASH_CLIENT_SECRET (API Key)
const CLIENT_ID = Deno.env.get('MONCASH_CLIENT_ID') || '';
const CLIENT_SECRET = Deno.env.get('MONCASH_CLIENT_SECRET') || '';

// URL de l'API MonCash pour l'authentification (Sandbox)
const AUTH_URL = 'https://sandbox.moncashbutton.digicelgroup.com/Moncash-API/oauth/token';

// Cache pour stocker le jeton et son expiration pour optimiser les performances
let accessToken: string | null = null;
let tokenExpiry: number = 0;

/**
 * Tente d'obtenir un jeton d'accès MonCash via OAuth 2.0 (client_credentials).
 * Utilise une mise en cache simple pour éviter des appels d'authentification répétés.
 * @returns Le jeton d'accès MonCash.
 */
async function getAccessToken(): Promise<string> {
    const now = Date.now();

    // 1. Vérifie si le jeton est encore valide dans le cache
    if (accessToken && now < tokenExpiry) {
        return accessToken;
    }

    // 2. Vérifie si les identifiants sont présents (doivent être dans le Vault)
    if (!CLIENT_ID || !CLIENT_SECRET) {
        throw new Error('Erreur de configuration: Les clés MonCash sont manquantes dans le Supabase Vault.');
    }

    // 3. Effectue l'appel API pour obtenir un nouveau jeton
    try {
        // Encodage Base64 des identifiants (requis par MonCash)
        const credentials = btoa(`${CLIENT_ID}:${CLIENT_SECRET}`);
        
        const response = await fetch(AUTH_URL, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Authorization': `Basic ${credentials}`,
            },
            // Corps standard pour une demande de jeton client_credentials
            body: 'scope=read&grant_type=client_credentials'
        });

        const data = await response.json();

        if (response.ok && data.access_token) {
            accessToken = data.access_token;
            // Calcule l'expiration (30 secondes d'avance pour éviter les jetons périmés)
            tokenExpiry = now + (data.expires_in * 1000) - 30000;
            return accessToken;
        } else {
            console.error('Erreur MonCash Auth:', data);
            throw new Error('Échec de l\'authentification MonCash. Vérifiez les clés dans le Vault.');
        }

    } catch (error) {
        console.error('Erreur réseau/générale:', error);
        throw new Error('Erreur interne de la Passerelle Efyso lors de l\'authentification.');
    }
}

// Fonction principale : Point d'entrée de la Edge Function (URL d'Alerte)
serve(async (req) => {
    // La logique future sera ici :
    // 1. Gérer les requêtes POST du Webhook (MonCash Alert)
    // 2. Gérer les requêtes GET pour démarrer une transaction
    
    // Pour l'instant, nous testons juste l'authentification:
    try {
        // Tente d'obtenir le jeton pour vérifier que l'authentification fonctionne
        const token = await getAccessToken();

        return new Response(
            JSON.stringify({
                status: 'ok',
                message: 'Passerelle Efyso active. Authentification MonCash réussie.',
                // On renvoie la longueur du jeton pour prouver le succès sans exposer le secret
                token_length: token.length 
            }),
            {
                headers: { 'Content-Type': 'application/json' },
                status: 200
            }
        );

    } catch (error) {
        return new Response(
            JSON.stringify({
                status: 'error',
                message: (error as Error).message
            }),
            {
                headers: { 'Content-Type': 'application/json' },
                status: 500
            }
        );
    }
});
