# Deployment Instructions for Maintainers

1. if needed, clone repo local
2. switch to main branch
3. fetch the latest changes from main
4. tox -e docs 
5. tox -e clean 
6. git tag v#.#.# 
7. tox -e build 
8. git -b release/v#.#.# branch 
9. git push release/v#.#.# 
10. push git tag v#.#.# to remote 
11. gh release create v#.#.# --generate-notes     
12. gh release upload v#.#.# dist/cvss_rescore-#.#.#-py3-none-any.whl
13. gh release upload v#.#.# dist/cvss_rescore-#.#.#.tar.gz
14. doppler run -- tox -e publish -- --repository pypi --verbose
