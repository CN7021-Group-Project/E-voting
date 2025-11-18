const mysql = require('mysql2/promise');

// This function finds candidate that similar voters have voted for
async function getRecommendations(voterId, electionId, dbConfig) {
    const connection = await mysql.createConnection(dbConfig);

    try {
        // Step 1: Find voters who voted for the same candidates as this voter
        const [similarVoters] = await connection.execute(
            `SELECT DISTINCE v1.voter_id
            FROM voting_history v1
            JOIN voting_history v2 ON v1.candidate_id = v2.candidate_id
            WHERE v2.voter_id = ?
            AND v1.voter_id != ?
            LIMIT 5
            `, [voterId, voterId]);

            if (similarVoters.length === 0) {
                // If no similar voters, just return popular candidates
                return await getPopularCandidates(electionId, dbConfig);
            }

            // Step 2: Get candidates those similar voters voted for
            const similarVotersIds = similarVoters.map(v => v.voter_id);
            const placeholders = similarVotersIds.map(() => '?').join(',');

            const [recommendations] = await connection.execute(
                `SELECT c.*, COUNT(*) as vote_count
                FROM candidates c
                JOIN voting_history vh ON c.id = vh.candidate_id
                WHERE vh.voter_id IN (${placeholders})
                AND vh.election_id = ?
                AND c.id NOT IN(
                    SELECT candidate_id FROM voting_history
                    WHERE voter_id = ? AND election_id = ?
                )
                    GROUP BY c.id
                    ORDER BY vote_count DESC
                    LIMIT 5
                    `, [...similarVotersIds, electionId, voterId, electionId]
            );

            return recommendations;
    } finally {
        await connection.end()
    }
}

// This function gets the most popular candidates
async function getPopularCandidates(electionId, dbConfig) {
    const connection = await mysql.createConnection(dbConfig);

    try {
        const [candidates] = await connection.execute(`
            SELECT c.*, COUNT(vh.id) as vote_count
            FROM candidates c
            LEFT JOIN voting_history vh ON c.id = vh.candidate_id
            WHERE c.election_id = ?
            GROUP BY c.id
            ORDER BY vote_count DESC
            LIMIT 5
            `,[electionId]
        );
        return candidates;
    }
    finally {
        await connection.end()
    }

}

module.exports = {
    getRecommendations,
    getPopularCandidates
};