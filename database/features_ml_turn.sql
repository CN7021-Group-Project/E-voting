CREATE OR REPLACE VIEW ml_turnout_features AS
SELECT 
    e.id AS election_id,
    e.title,

    COUNT(c.id) AS num_candidates,

    DATEDIFF(e.end_date, e.start_date) AS duration_days,
    
    (SELECT COUNT(*) FROM users WHERE role='voter') AS total_registered_voters,

    (SELECT COUNT(*)
     FROM votes v
     WHERE v.election_id = e.id) AS total_votes,

    (SELECT COUNT(*)
     FROM votes v
     WHERE v.election_id = e.id) / 
    (SELECT COUNT(*) FROM users WHERE role='voter') AS turnout_ratio,

    ---- FIXED: turnout now 0 or 1, no NaN ----
    CASE 
        WHEN ((SELECT COUNT(*) FROM votes v WHERE v.election_id=e.id) /
              (SELECT COUNT(*) FROM users WHERE role='voter')) > 0.60 THEN 1
        ELSE 0
    END AS turnout_high

FROM elections e
LEFT JOIN candidates c ON c.election_id=e.id
GROUP BY e.id;
