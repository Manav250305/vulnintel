% Phase 4, Step 2 -- power iteration eigenvector centrality (Module 6)
%
% Loads the co-occurrence matrix built in build_cooccurrence.py, symmetrizes
% it (the matrix was built upper-triangle-only, per design), and computes
% the dominant eigenvector via power iteration -- not eig() -- since the
% manual computation is the module content being demonstrated (design doc
% Section 6.2).

A = csvread('data/cooccurrence_matrix.csv');
n = size(A, 1);
printf('Loaded %dx%d co-occurrence matrix\n', n, n);

A = A + A';  % symmetrize

v = ones(n,1) / sqrt(n);
converged = false;
for k = 1:100
  v_new = A * v;
  norm_v = norm(v_new);
  if norm_v == 0
    error('Zero vector encountered at iteration %d -- matrix may be disconnected', k);
  endif
  v_new = v_new / norm_v;
  delta = norm(v_new - v);
  if delta < 1e-8
    printf('Converged after %d iterations (delta=%.2e)\n', k, delta);
    converged = true;
    v = v_new;
    break;
  endif
  v = v_new;
endfor

if !converged
  printf('Did not converge within 100 iterations (final delta=%.2e)\n', delta);
endif

% Rayleigh quotient gives the corresponding eigenvalue (dominant eigenvalue
% of the symmetrized co-occurrence matrix), reported for reference/sanity.
lambda = (v' * A * v) / (v' * v);
printf('Dominant eigenvalue (Rayleigh quotient): %.4f\n', lambda);

csvwrite('data/centrality_scores.csv', v);
printf('Wrote data/centrality_scores.csv (%d scores)\n', n);